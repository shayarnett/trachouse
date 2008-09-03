#
#   Trac to Lighthouse ticket importer
#
#   Original Author: Shay Arnett <shayarnett@gmail.com>
#
#   Contributions by :
#       Maxim Chernyak <max@bitsonnet.com>
#       João Abecasis <joao@abecasis.name>
#
#
#   NOTES
#   -----
#
#   You'll need to get lighthouse.rb from
#   http://ar-code.svn.engineyard.com/lighthouse-api/lib
#
#   Enter Lighthouse and Trac configuration data in the ###marked### sections.
#
#   Usage:
#
#       require 'trachouse'
#
#       t = Ticket.new
#
#       # grabs all tickets from trac
#       tickets = t.populate_tickets
#       # import tickets to lighthouse
#       t.import_tickets(tickets)
#       # profit
#
#   You may want to inspect tickets and import a subset for testing, before
#   bulk processing all tickets.


# Copyright (c) 2008 Shay Arnett
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.


require 'hpricot'
require 'net/http'
require 'activeresource'
require 'lighthouse'

class Ticket < ActiveResource::Base
  include Lighthouse

  ############
  ### Lighthouse configuration
  ###

  # Lighthouse Account Name -- NOT your username!
  Lighthouse.account = 'foo_bar'
  # Lighthouse API token
  Lighthouse.token = 'xxxxxxxxx'

  ###
  ### END of Lighthouse configuration
  ############

  def initialize

    ############
    ### Trac configuration
    ###

    # URL pointing to root of Trac installation. Don't include '/wiki/WikiStart'
    # and such. Don't include trailing slash...
    @trac_url = 'http://trac.example.com/myproject/trac'

    # Credentials are required to access user data.
    # Does Trac use basic http authentication?
    @trac_basic_auth = true
    @trac_username = 'tracuser@email.com'
    @trac_password = 'password'

    ###
    ### END of Trac configuration
    ############

    @tickets = []
    @ticket = {}
    @ticket_list = []

    @useragent = 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-us) AppleWebKit/523.10.6 (KHTML, like Gecko) Version/3.0.4 Safari/523.10.6'

    trac_uri = URI.parse(@trac_url)
    @trac_host = trac_uri.host
    @trac_port = trac_uri.port
    @trac_path = trac_uri.path

    @trac_address = "http://#{@trac_host}:#{@trac_port}/"

    # setup headers for grabbing cookie and tiket info
    @headers = {
      'Referer' => @trac_url,
      'User-Agent' => @useragent
    }

    # setup connection
    @http = Net::HTTP.new(@trac_host, @trac_port)

    #setup project_ids and associated trac components
    # :project_id should be the lighthouse id of the project
    #  you want to import the tickets to
    #
    # :components should be an array of the trac components you wish
    #  to import into this project
    #
    # project_1 = { :project_id => 1234,
    #               :components => ['Core','Module 1', 'etc']}
    # project_2 = { etc }

    merb_core = { :project_id => 7433,
                  :components => [ 'Merb',
                                   'Web Site',
                                   'Web site',
                                   'Documentation',
                                   'Routing',
                                   'Views']
                }

    merb_more = { :project_id => 7435,
                     :components => [ 'Generators',
                                      'Rspec Harness']
                   }

    merb_plugins = { :project_id => 7588,
                     :components => [ 'Plugin: DataMapper',
                                      'Plugin: ActiveRecord',
                                      'Plugins']
                   }
    # add all your project hashes to @projects
    #
    # this could have been combined with above, but tended to be less readable
    # after adding a couple projects
    @projects = [ merb_core, merb_more, merb_plugins ]
  end

  def tag_prep(tags)
    returning tags do |tag|
      tag.collect! do |t|
        unless tag.blank?
          t.downcase!
          t.gsub! /(^')|('$)/, ''
          t.gsub! ' ','_'
          t.gsub! /[^a-z0-9 \-_@\!']/, ''
          t.strip!
          t
        end
      end
      tag.compact!
      tag.uniq!
    end
  end

  def get_project(ticket)
    project_id = nil
    @projects.each do |project|
      project_id = project[:project_id] if project[:components].include? ticket[:component]
      break unless project_id.nil?
    end
    return project_id
  end

  def build_ticket(doc, ticket_num)
    # this is all based on a pretty standard trac template
    # if you have done any customizing you will need to check your html
    # and change the necessary Hpricot searches to pull the correct data

    # build the base ticket
    ticket = { :title => (doc/"h2.summary").inner_html,
               :trac_url => '"Original Trac Ticket":' + @trac_url + '/ticket/' + ticket_num,
               :reporter => (doc/"//td[@headers='h_reporter']").inner_html,
               :priority => (doc/"//td[@headers='h_priority']").inner_html,
               :component => (doc/"//td[@headers='h_component']").inner_html,
               :status => (doc/"span.status").first.inner_html,
               :milestone => (doc/"//td[@headers='h_milestone']").inner_html,
               :description => (doc/"div.description").inner_html,
               :comments => [],
               :attachments => []
             }

    # clean up the description
    Hpricot(ticket[:description]).search("h3").remove
    ticket[:description].gsub!(/<\/?pre( class=\"wiki\")?>/,"@@@\n")
    ticket[:description].gsub!(/<\/?[^>]*>/, "")
    ticket[:description] = unescapeHTML(ticket[:description].gsub!(/\n\s*\n\s*\n/,"\n\n"))

    # gather and clean up the ticket changes
    changes = []
    (doc/"div.change").each do |c|
      changes << { :name => (c/"h3").inner_html, :comment => (c/"[.comment]|[.changes]").inner_html }
    end
    changes.each do |change|
      change[:name].gsub!(/<\/?[^>]*>/, "")
      change[:name].strip!
      change[:comment].gsub!(change[:name],"")
      change[:comment].gsub!(/<\/?[^>]*>/, "")
      change[:comment].gsub!(/\n\s*\n\s*\n/,"\n\n")
      ticket[:comments] << change[:name] + "\n@@@\n" + change[:comment] + "\n@@@\n"
    end
    ticket[:comments] = unescapeHTML(ticket[:comments].join("\n"))
    ticket[:comments].gsub!(/\((follow|in)[^\)]*\)/,'')

    # gather and cleanup the attachments
    (doc/"dl.attachments/dt/a").each do |a|
      ticket[:attachments] << + "#{@trac_address}#{a.attributes['href']}"
    end
    ticket[:attachments] = unescapeHTML(ticket[:attachments].join("\n"))

    # put together the final body
    ticket[:body] = [ "Originally posted on Trac by #{ticket[:reporter]}", ticket[:trac_url], ticket[:description], "h3. Trac Attachments", ticket[:attachments], "h3. Trac Comments", ticket[:comments]].join("\n")
    ticket[:tags] = [ticket[:priority],ticket[:component]]
    ticket[:tags] << "patch" if ticket[:title].match /patch/i
    ticket[:project_id] = get_project(ticket)
    return ticket
  end

  def unescapeHTML(string)
    # from CGI.rb - don't need the slow just the unescape
    if string == nil
      return ''
    end

    string.gsub(/&(.*?);/n) do
      match = $1.dup
      case match
      when /\Aamp\z/ni           then '&'
      when /\Aquot\z/ni          then '"'
      when /\Agt\z/ni            then '>'
      when /\Alt\z/ni            then '<'
      when /\A#0*(\d+)\z/n       then
        if Integer($1) < 256
          Integer($1).chr
        else
          if Integer($1) < 65536 and ($KCODE[0] == ?u or $KCODE[0] == ?U)
            [Integer($1)].pack("U")
          else
            "&##{$1};"
          end
        end
      when /\A#x([0-9a-f]+)\z/ni then
        if $1.hex < 256
          $1.hex.chr
        else
          if $1.hex < 65536 and ($KCODE[0] == ?u or $KCODE[0] == ?U)
            [$1.hex].pack("U")
          else
            "&#x#{$1};"
          end
        end
      else
        "&#{match};"
      end
    end
  end

  def steal_cookie
    # get request to gather tokens needed to hijack cookie
    resp = @http.request_get(@trac_path + '/login', {'User-Agent' => @useragent})
    cookie = resp.response['Set-Cookie']
    resp.body.match(/TOKEN\" value\=\"(\w+)\"/)
    url_params = "user=#{@trac_username}&password=#{@trac_password}&__FORM_TOKEN=#{$1}"
    @headers = {
      'Cookie' => cookie,
      'Referer' => @trac_url + '/login',
      'Content-Type' => 'application/x-www-form-urlencoded'
    }
    # post to login and grab cookie for later
    resp = @http.request_post(@trac_path + '/login', url_params, @headers)
    cookie = resp.response['Set-Cookie']

    @headers = {
      'Cookie' => cookie
    }
  end

  def get_html_for_ticket(ticket)
    #change url if you go somewhere other than /ticket/1 to pull up ticket #1
    ticket_url = @trac_path + "/ticket/#{ticket}"

    if @trac_basic_auth
      resp = Net::HTTP.start(@trac_host, @trac_port) do |http|
        req = Net::HTTP::Get.new(ticket_url)
        req.basic_auth @trac_username, @trac_password
        resp = http.request(req)
      end
    else
      # change url in get2() if you go somewhere other than /ticket/1 to pull up ticket #1
      resp = @http.request_get(ticket_url, @headers)
    end
    Hpricot(unescapeHTML(resp.body)) if resp.code == '200'
  end

  def create_ticket(trac_ticket)
    ticket = Lighthouse::Ticket.new(:project_id => trac_ticket[:project_id])
    ticket.title = trac_ticket[:title].to_s
    ticket.tags = tag_prep(trac_ticket[:tags])
    ticket.body = trac_ticket[:body].to_s
    ticket.save
  end

  def import_tickets(tickets)
    if not @trac_basic_auth
      steal_cookie
    end

    new_tickets = []
    tickets.each do |ticket|
      # grab the page for this ticket
      ticket_html = get_html_for_ticket(ticket)
      # pull data for ticket
      new_ticket = build_ticket(ticket_html,ticket)
      # add to @tickets[]
      new_tickets << new_ticket
    end

    # create and save to lighthouse
    new_tickets.each do |ticket|
      create_ticket(ticket)
    end
  end

  def populate_tickets
    # url should be the path to a trac report that shows you all tickets from
    # all components
    url = @trac_path +
            '/query?order=id' +
                '&status=new' +
                '&status=assigned' +
                '&status=reopened'

    ticket_list = []

    if @trac_basic_auth
      resp = Net::HTTP.start(@trac_host, @trac_port) do |http|
        req = Net::HTTP::Get.new(url)
        req.basic_auth @trac_username, @trac_password
        resp = http.request(req)
      end
    else
      resp = @http.request_get(url, {'User-Agent' => @useragent})
    end
    html = Hpricot(resp.body)
    (html/'.id/a').each do |a|
     a.inner_html =~ /^(\d{1,3})$/
     # For some reason, the XPath expression also matches the table header, with
     # class="id asc".  We work around that.
     if $1; ticket_list << $1; end
    end
   ticket_list
  end

end
