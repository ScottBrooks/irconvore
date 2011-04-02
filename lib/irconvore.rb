require 'rubygems'
require 'eventmachine'
require 'em-ircd.rb'

class IRConvore
  def initialize
    #
    # load config
    #
    begin
      require 'json'
      $config = IRC::DefaultConfig.dup.merge(
        JSON.parse(File.read(ARGV[0] || 'server-config.json'))
      )
    rescue => ex
      $config = IRC::DefaultConfig.dup
    end


    EM.run do
      puts "loading config for %s:\n%s" % [ $config['network_name'], JSON.pretty_generate($config) ]

      server = IRC::Server.new($config['network_name'], IRC::Users, IRC::Channels)

      server_sockets = $config['listen'].map{|i|
        EM.start_server(i['interface'], i['port'].to_i, IRC::Connection, server)
        puts "started em-ircd server at: %s:%s" % i.values_at('interface', 'port')
      }

      EM.add_periodic_timer(60){
        server.clients.each{|c| c.send_reply(nil, :ping, server.name) }
      }
    end

  end
end
