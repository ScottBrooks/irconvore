#
# This file pulled from 
# https://github.com/lian/em-ircd
#

#
# load numerics.json
#
begin
  require 'json'

  Numerics_json = <<-EOF
{
  "000": [ "INT_SUCCESS", null ],
  "001": [ "RPL_WELCOME", ":Welcome to the IRC Network %s" ],
  "002": [ "RPL_YOURHOST", ":Your host is %s, running version %s" ],
  "003": [ "RPL_CREATED", ":This server was created %s" ],
  "004": [ "RPL_MYINFO", "%s %s %s %s" ],
  "005": [ "RPL_ISUPPORT", "%s" ],
  "200": [ "RPL_TRACELINK", null ],
  "201": [ "RPL_TRACECONNECTING", null ],
  "202": [ "RPL_TRACEHANDSHAKE", null ],
  "203": [ "RPL_TRACEUNKNOWN", null ],
  "204": [ "RPL_TRACEOPERATOR", null ],
  "205": [ "RPL_TRACEUSER", null ],
  "206": [ "RPL_TRACESERVER", null ],
  "207": [ "RPL_TRACESERVICE", null ],
  "208": [ "RPL_TRACENEWTYPE", null ],
  "209": [ "RPL_TRACECLASS", null ],
  "210": [ "RPL_TRACERECONNECT", null ],
  "211": [ "RPL_STATSLINKINFO", null ],
  "212": [ "RPL_STATSCOMMANDS", null ],
  "213": [ "RPL_STATSCLINE", null ],
  "214": [ "RPL_STATSNLINE", null ],
  "215": [ "RPL_STATSILINE", null ],
  "216": [ "RPL_STATSKLINE", null ],
  "217": [ "RPL_STATSQLINE", null ],
  "218": [ "RPL_STATSYLINE", null ],
  "219": [ "RPL_ENDOFSTATS", null ],
  "221": [ "RPL_UMODEIS", "%s" ],
  "231": [ "RPL_SERVICEINFO", null ],
  "232": [ "RPL_ENDOFSERVICES", null ],
  "233": [ "RPL_SERVICE", null ],
  "234": [ "RPL_SERVLIST", null ],
  "235": [ "RPL_SERVLISTEND", null ],
  "240": [ "RPL_STATSVLINE", null ],
  "241": [ "RPL_STATSLLINE", null ],
  "242": [ "RPL_STATSUPTIME", null ],
  "243": [ "RPL_STATSOLINE", null ],
  "244": [ "RPL_STATSSLINE", null ],
  "246": [ "RPL_STATSPING", null ],
  "247": [ "RPL_STATSBLINE", null ],
  "250": [ "RPL_STATSDLINE", null ],
  "251": [ "RPL_LUSERCLIENT", ":There are %d users and %d invisible on %d server(s)" ],
  "252": [ "RPL_LUSEROP", "%d :operator(s) online" ],
  "253": [ "RPL_LUSERUNKNOWN", "%d :unknown connection(s)" ],
  "254": [ "RPL_LUSERCHANNELS", "%d :channels formed" ],
  "255": [ "RPL_LUSERME", ":I have %d client(s) and %d server(s)" ],
  "256": [ "RPL_ADMINME", "%s :Administrative info" ],
  "257": [ "RPL_ADMINLOC1", ":%s" ],
  "258": [ "RPL_ADMINLOC2", ":%s" ],
  "259": [ "RPL_ADMINEMAIL", ":%s" ],
  "261": [ "RPL_TRACELOG", null ],
  "262": [ "RPL_TRACEEND", null ],
  "263": [ "RPL_TRYAGAIN", null ],
  "265": [ "RPL_LOCALUSERS", ":Current Local Users: %d Max: %d" ],
  "266": [ "RPL_GLOBALUSERS", ":Current Global Users: %d Max: %d" ],
  "300": [ "RPL_NONE", null ],
  "301": [ "RPL_AWAY", "%s :%s" ],
  "302": [ "RPL_USERHOST", null ],
  "303": [ "RPL_ISON", ":%s" ],
  "305": [ "RPL_UNAWAY", ":You are no longer marked as being away" ],
  "306": [ "RPL_NOWAWAY", ":You have been marked as being away" ],
  "311": [ "RPL_WHOISUSER", "%s %s %s * :%s" ],
  "312": [ "RPL_WHOISSERVER", "%s %s" ],
  "313": [ "RPL_WHOISOPERATOR", "%s :is an IRC operator" ],
  "314": [ "RPL_WHOWASUSER", "%s %s %s * :%s" ],
  "315": [ "RPL_ENDOFWHO", "%s :End of /WHO list." ],
  "316": [ "RPL_WHOISCHANOP", null ],
  "317": [ "RPL_WHOISIDLE", "%s %d :seconds idle" ],
  "318": [ "RPL_ENDOFWHOIS", "%s :End of WHOIS list" ],
  "319": [ "RPL_WHOISCHANNELS", "%s :%s" ],
  "321": [ "RPL_LISTSTART", "Channel :Users Name" ],
  "322": [ "RPL_LIST", "%s %s :%s" ],
  "323": [ "RPL_LISTEND", ":End of /LIST" ],
  "324": [ "RPL_CHANNELMODEIS", "%s %s" ],
  "325": [ "RPL_UNIQOPIS", "%s %s" ],
  "329": [ "RPL_CREATIONTIME", "%s %s" ],
  "331": [ "RPL_NOTOPIC", "%s :No topic is set" ],
  "332": [ "RPL_TOPIC", "%s :%s" ],
  "333": [ "RPL_TOPICWHOTIME", "%s %s %d" ],
  "341": [ "RPL_INVITING", "%s %s" ],
  "342": [ "RPL_SUMMONING", "%s :Summoning user to IRC" ],
  "346": [ "RPL_INVITELIST", "%s %s" ],
  "347": [ "RPL_ENDOFINVITELIST", "%s :End of channel invite list" ],
  "348": [ "RPL_EXCEPTLIST", "%s %s" ],
  "349": [ "RPL_ENDOFEXCEPTLIST", "%s :End of channel exception list" ],
  "351": [ "RPL_VERSION", "%s %s :%s" ],
  "352": [ "RPL_WHOREPLY", "%s %s %s %s %s %s :%d %s" ],
  "353": [ "RPL_NAMREPLY", "= %s :%s" ],
  "361": [ "RPL_KILLDONE", null ],
  "362": [ "RPL_CLOSING", null ],
  "363": [ "RPL_CLOSEEND", null ],
  "364": [ "RPL_LINKS", null ],
  "365": [ "RPL_ENDOFLINKS", null ],
  "366": [ "RPL_ENDOFNAMES", "%s :End of /NAMES list." ],
  "367": [ "RPL_BANLIST", null ],
  "368": [ "RPL_ENDOFBANLIST", null ],
  "369": [ "RPL_ENDOFWHOWAS", "%s :End of WHOWAS" ],
  "371": [ "RPL_INFO", ":%s" ],
  "372": [ "RPL_MOTD", ":- %s" ],
  "373": [ "RPL_INFOSTART", null ],
  "374": [ "RPL_ENDOFINFO", ":End of INFO list" ],
  "375": [ "RPL_MOTDSTART", ":- %s Message of the day -" ],
  "376": [ "RPL_ENDOFMOTD", ":End of /MOTD command." ],
  "381": [ "RPL_YOUREOPER", ":You are now an IRC operator" ],
  "382": [ "RPL_REHASHING", "%s :Rehashed" ],
  "383": [ "RPL_YOURESERVICE", null ],
  "384": [ "RPL_MYPORTIS", null ],
  "391": [ "RPL_TIME", "%s :%s" ],
  "392": [ "RPL_USERSSTART", null ],
  "393": [ "RPL_USERS", null ],
  "394": [ "RPL_ENDOFUSERS", null ],
  "395": [ "RPL_NOUSERS", null ],
  "400": [ "ERR_UNKNOWNERROR", "%s" ],
  "401": [ "ERR_NOSUCHNICK", "%s :No such nick/channel" ],
  "402": [ "ERR_NOSUCHSERVER", null ],
  "403": [ "ERR_NOSUCHCHANNEL", "%s :No such channel" ],
  "404": [ "ERR_CANNOTSENDTOCHAN", null ],
  "405": [ "ERR_TOOMANYCHANNELS", "%s :You have joined too many channels" ],
  "406": [ "ERR_WASNOSUCHNICK", null ],
  "407": [ "ERR_TOOMANYTARGETS", null ],
  "408": [ "ERR_NOSUCHSERVICE", null ],
  "409": [ "ERR_NOORIGIN", null ],
  "411": [ "ERR_NORECIPIENT", null ],
  "412": [ "ERR_NOTEXTTOSEND", null ],
  "413": [ "ERR_NOTOPLEVEL", null ],
  "414": [ "ERR_WILDTOPLEVEL", null ],
  "415": [ "ERR_BADMASK", null ],
  "421": [ "ERR_UNKNOWNCOMMAND", "%s :Unknown command" ],
  "422": [ "ERR_NOMOTD", ":MOTD File is missing" ],
  "423": [ "ERR_NOADMININFO", null ],
  "424": [ "ERR_FILEERROR", null ],
  "431": [ "ERR_NONICKNAMEGIVEN", null ],
  "432": [ "ERR_ERRONEUSNICKNAME", "%s :Erroneous nickname" ],
  "433": [ "ERR_NICKNAMEINUSE", "%s :Nickname is already in use" ],
  "436": [ "ERR_NICKCOLLISION", null ],
  "437": [ "ERR_UNAVAILRESOURCE", null ],
  "441": [ "ERR_USERNOTINCHANNEL", "%s %s :User(s) not on that channel" ],
  "442": [ "ERR_NOTONCHANNEL", "%s :You're not on that channel" ],
  "443": [ "ERR_USERONCHANNEL", "%s %s :is already on channel" ],
  "444": [ "ERR_NOLOGIN", null ],
  "445": [ "ERR_SUMMONDISABLED", ":Don't see the point of SUMMON, so its disabled" ],
  "446": [ "ERR_USERSDISABLED", null ],
  "449": [ "ERR_NOTIMPLEMENTED", "%s :Not Implemented" ],
  "451": [ "ERR_NOTREGISTERED", ":You have not registered" ],
  "461": [ "ERR_NEEDMOREPARAMS", "%s :Not enough parameters" ],
  "462": [ "ERR_ALREADYREGISTRED", ":Unauthorized command (already registered)" ],
  "463": [ "ERR_NOPERMFORHOST", null ],
  "464": [ "ERR_PASSWDMISMATCH", ":Password incorrect" ],
  "465": [ "ERR_YOUREBANNEDCREEP", null ],
  "466": [ "ERR_YOUWILLBEBANNED", null ],
  "467": [ "ERR_KEYSET", null ],
  "471": [ "ERR_CHANNELISFULL", null ],
  "472": [ "ERR_UNKNOWNMODE", null ],
  "473": [ "ERR_INVITEONLYCHAN", null ],
  "474": [ "ERR_BANNEDFROMCHAN", null ],
  "475": [ "ERR_BADCHANNELKEY", "%s :Cannot join channel (+k)" ],
  "476": [ "ERR_BADCHANMASK", null ],
  "477": [ "ERR_NOCHANMODES", null ],
  "478": [ "ERR_BANLISTFULL", null ],
  "481": [ "ERR_NOPRIVILEGES", ":Permission Denied - You're not an IRC operator" ],
  "482": [ "ERR_CHANOPRIVSNEEDED", "%s :You're not a channel operator" ],
  "483": [ "ERR_CANTKILLSERVER", null ],
  "484": [ "ERR_RESTRICTED", null ],
  "485": [ "ERR_UNIQOPPRIVSNEEDED", null ],
  "491": [ "ERR_NOOPERHOST", ":No O-lines for your host" ],
  "492": [ "ERR_NOSERVICEHOST", null ],
  "501": [ "ERR_UMODEUNKNOWNFLAG", ":Unknown MODE flag" ],
  "502": [ "ERR_USERSDONTMATCH", ":Cannot change mode for other users" ],
  "901": [ "ERR_NOTADAEMON", null ]
}
EOF

  module IRC
    Numerics = JSON.parse(Numerics_json || File.read('doc/numerics.json'))
    Msg = {}; Numerics.each{|k,v| Msg[v[0]] = [k,*v[1..-1]] }
  end
rescue => ex
  p ex.message
  raise "failed to load: numerics.json"
end


CommandProc_Table = {

  'PASS' => proc{|args,conn| },

  'NICK' => proc{|args,conn|
    if args.empty? || args[0].size < 1
      conn.send_numeric(*IRC::Msg['ERR_NONICKNAMEGIVEN'])
    elsif !IRC.validate_nick(args[0])
      conn.send_numeric(*IRC::Msg['ERR_ERRONEUSNICKNAME'], args[0])
    elsif IRC::Users.find(args[0])
      conn.send_numeric(*IRC::Msg['ERR_NICKNAMEINUSE'], args[0])
    else
      conn.nick = args[0]
    end
  },

  'USER' => proc{|args,conn|
    if args.size < 4
      conn.send_numeric(*IRC::Msg['ERR_NEEDMOREPARAMS'], 'USER')
    elsif conn.is_registered?
      conn.send_numeric(*IRC::Msg['ERR_ALREADYREGISTRED'])
    else
      conn.ident    = args[0]
      conn.realname = args[3]
      conn.check_registration
    end
  },

  'OPER' => proc{|args,conn|
    name = args.any? && args.shift.downcase
    pass = args.shift

    if $config['opers'].select{|oper|oper['login'].downcase==name && oper['pass']==pass}.first
      conn.opered = true
      conn.send_numeric(*IRC::Msg['RPL_YOUREOPER'])
      conn.join_channel($config['oper_channel']) if $config['oper_channel']
    else
      conn.send_numeric(*IRC::Msg['ERR_NOOPERHOST'])
    end
  },

  'MODE' => proc{|args,conn|
    target = conn.server.channels.find(args[0]) || conn.server.users.find(args[0])

    if target.is_a? IRC::Channel
      channel = target
      if args.size < 2
        conn.send_numeric(*IRC::Msg['RPL_CHANNELMODEIS'],
                          channel.name, "+#{channel.modes}")
        conn.send_numeric(*IRC::Msg['RPL_CREATIONTIME'],
                          channel.name, channel.mode_timestamp.to_i)
      else
        IRC.change_chmode(conn, channel, args[1], args[2..-1])
      end
    elsif target.is_a? IRC::Client
      if args.size < 2
        conn.send_numeric(*IRC::Msg['RPL_UMODEIS'], '+'+conn.umodes)
      elsif target == self
        IRC.change_umode(self, args[1], args[2..-1])
      else # someone else
      end
    else
      conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], args[0])
    end
  },

  'SERVICE' => proc{|args,conn| },

  'QUIT' => proc{|args,conn|
    conn.close(args[0] || 'Client quit')
  },

  'SQUIT' => proc{|args,conn| },

  'JOIN' => proc{|args,conn|
    if args.empty? || args[0].size < 1
      conn.send_numeric(*IRC::Msg['ERR_NEEDMOREPARAMS'], 'JOIN')
    else
      #target  = args[0]
      args[0].split(",").each{|target| # because of JOIN #fo,#ba input
      channel = conn.server.channels.find(target)
      
      if !IRC.validate_chan(target)
        conn.send_numeric(*IRC::Msg['ERR_NOSUCHCHANNEL'], target)
      elsif conn.channels.size >= ($config['max_channels_per_user'] || 4).to_i
        conn.send_numeric(*IRC::Msg['ERR_TOOMANYCHANNELS'], target)
      elsif channel && channel.has_mode?('i')
        conn.send_numeric(*IRC::Msg['ERR_INVITEONLYCHAN'], '%s', 'Cannot join channel (+i)')
      else
        channel ||= conn.server.channels.find_or_create(target)
        if !channel.users.include?(conn)
          channel.join(conn)
          # send topic
          conn.send_numeric(*IRC::Msg['RPL_TOPIC'], channel.name, channel.topic)
          conn.send_numeric(*IRC::Msg['RPL_TOPICWHOTIME'],
                            channel.name, channel.topic_author, channel.topic_timestamp.to_i)
          # send names
          nicks   = channel.users.map{|user| IRC.prefix_for(channel) + user.nick }
          conn.send_numeric(*IRC::Msg['RPL_NAMREPLY'],   channel.name, nicks.join(' '))
          conn.send_numeric(*IRC::Msg['RPL_ENDOFNAMES'], channel.name)
        end
      end
      }
    end
  },

  'PART' => proc{|args,conn|
    channel = conn.server.channels.find(args[0])
    if !channel
      conn.send_numeric(*IRC::Msg['ERR_NOSUCHCHANNEL'], args[0])
    elsif channel.users.include?(conn)
      channel.part(conn, args[1] || 'Leaving')
    else
      conn.send_numeric(*IRC::Msg['ERR_NOSUCHCHANNEL'], args[0])
    end
  },

  'TOPIC' => proc{|args,conn|
    channel = conn.server.channels.find(args[0].to_s)
    if args.size < 2
      if channel.topic
        conn.send_numeric(*IRC::Msg['RPL_TOPIC'], channel.name, channel.topic)
        conn.send_numeric(*IRC::Msg['RPL_TOPICWHOTIME'],
                          channel.name, channel.topic_author, channel.topic_timestamp.to_i)
      else
        conn.send_numeric(*IRC::Msg['RPL_NOTOPIC'], channel.name)
      end
    elsif channel.has_mode?('t') && !IRC.is_op_or_better_on(channel, self)
      conn.send_numeric(*IRC::Msg['ERR_CHANOPRIVSNEEDED'], channel.name)
    else
      channel.set_topic args[1], conn
    end
  },

  'NAMES' => proc{|args,conn|
    channel = conn.server.channels.find(args[0])
    nicks   = channel.users.map{|user| IRC.prefix_for(channel) + user.nick }
    conn.send_numeric(*IRC::Msg['RPL_NAMREPLY'],   channel.name, nicks.join(' '))
    conn.send_numeric(*IRC::Msg['RPL_ENDOFNAMES'], channel.name)
  },

  'LIST' => proc{|args,conn|
    conn.send_numeric(*IRC::Msg['RPL_LISTSTART'])

    pattern, not_pattern = nil, nil
    min, max = nil, nil
    if args[0]
      args[0].split(',').each do |arg|
        if arg =~ /<([0-9]+)/
          max = $1.to_i
        elsif arg =~ />([0-9]+)/
          min = $1.to_i
        elsif arg[0,1] == '!'
          not_pattern = Regexp.escape(args[1][1..-1]).gsub('\*','.*').gsub('\?', '.')
          not_pattern = /^#{not_pattern}$/i
        else
          pattern = Regexp.escape(args[1].to_s).gsub('\*','.*').gsub('\?', '.')
          pattern = /^#{pattern}$/i
        end
      end
    end

    conn_channels = conn.channels
    conn.server.channels.each do |k,channel|
      next if channel.has_any_mode?('ps') && !conn_channels.include?(channel) && !@opered
      next if pattern && !(channel.name =~ pattern)
      next if not_pattern && channel.name =~ not_pattern
      next if min && !(channel.users.size > min)
      next if max && !(channel.users.size < max)
      topic = ' ' + (channel.topic || '')
      topic = "[+#{channel.modes}] #{topic}" if channel.modes
      conn.send_numeric(*IRC::Msg['RPL_LIST'],
                        channel.name, channel.users.size, topic)
    end
    conn.send_numeric(*IRC::Msg['RPL_LISTEND'])
  },

  'INVITE' => proc{|args,conn| },

  'KICK' => proc{|args,conn|
    if args.size < 2
      conn.send_numeric(*IRC::Msg['ERR_NEEDMOREPARAMS'], 'KICK')
    else
      channel, target = conn.server.channels.find(args[0]), conn.server.users.find(args[1])

      if !channel
        conn.send_numeric(*IRC::Msg['ERR_NOSUCHCHANNEL'], args[0])
      elsif !target
        conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], args[1])
      #elsif !target
      elsif !IRC.is_on(channel, target)
        conn.send_numeric(*IRC::Msg['ERR_CHANOPRIVSNEEDED'], "#{target.nick} #{channel.name}")
      elsif !IRC.is_op_on(channel, self)
        conn.send_numeric(*IRC::Msg['ERR_CHANOPRIVSNEEDED'], channel.name)
      else
        IRC.kicked_from(target, channel, conn, args[2] || conn.nick)
      end
    end
  },

  'PRIVMSG' => proc{|args,conn|
    target = conn.server.channels.find(args[0]) || conn.server.users.find(args[0])
    if target.is_a? IRC::Channel
      target.message(conn, args[1])
    elsif target.is_a? IRC::Client
      target.send_reply(conn.path, :privmsg, target.nick, args[1])
    else
      conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], args[0])
    end
  },

  'NOTICE' => proc{|args,conn|
    if !conn.opered
      conn.send_numeric(*IRC::Msg['RPL_INFO'], "Sorry, You have NO Permission to run NOTICE")
      conn.send_numeric(*IRC::Msg['ERR_NOPRIVILEGES'])
    else
      target = conn.server.channels.find(args[0]) || conn.server.users.find(args[0])
      if target.is_a? IRC::Channel
        target.notice(conn, args[1])
      elsif target.is_a? IRC::Client
        target.send_reply(conn.path, :notice, target.nick, args[1])
      else
        conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], args[0])
      end
    end
  },

  'MOTD' => proc{|args,conn|
		motd = $config['motd'] || nil #get_motd
		if motd
      conn.send_numeric(*IRC::Msg['RPL_MOTDSTART'], conn.server.name)
			motd.each_line{|line| conn.send_numeric(*IRC::Msg['RPL_MOTD'], line) }
      conn.send_numeric(*IRC::Msg['RPL_ENDOFMOTD'])
		else
      conn.send_numeric(*IRC::Msg['ERR_NOMOTD'])
		end
  },

  'LUSERS' => proc{|args,conn|
		opers     = conn.server.clients.select{|user| user.opered }.size
		invisible = conn.server.clients.select{|user| user.has_umode?('i') }.size
		total     = conn.server.clients.size
    conn.send_numeric(*IRC::Msg['RPL_LUSERCLIENT'],   total-invisible, invisible, 1)
    conn.send_numeric(*IRC::Msg['RPL_LUSEROP'],       opers)
    conn.send_numeric(*IRC::Msg['RPL_LUSERCHANNELS'], conn.server.channels.size)
    conn.send_numeric(*IRC::Msg['RPL_LUSERME'],       total, 0)
    conn.send_numeric(*IRC::Msg['RPL_LOCALUSERS'],    total, total)
    conn.send_numeric(*IRC::Msg['RPL_GLOBALUSERS'],   total, total)
  },

  'VERSION' => proc{|args,conn| 
		detailed = args[0]
		if detailed
			version = ['em-ircd-machine_0.1', conn.server.name, 'Rubinius  [Linux 2.6.ARCH]']
      conn.send_numeric(*IRC::Msg['RPL_VERSION'], *version)
			#conn.send_reply(conn.server.name, :notice, @nick, 'libcurl/7.19.4 zlib/1.2.3')
		end
		($config['features'] || []).dup.each_slice(13) do |slice| # Why 13? Ask freenode
			slice.map!{ |k,v| (v==true) ? k.upcase : "#{k.upcase}=#{v}" }
			slice << 'are supported by this server'
      conn.send_numeric(*IRC::Msg['RPL_ISUPPORT'], slice.join(' '))
		end
  },

  'STATS' => proc{|args,conn| },
  'LINKS' => proc{|args,conn| },
  'TIME' => proc{|args,conn| },
  'CONNECT' => proc{|args,conn| },
  'TRACE' => proc{|args,conn| },
  'ADMIN' => proc{|args,conn| },
  'INFO' => proc{|args,conn| },
  'SERVLIST' => proc{|args,conn| },
  'SQUERY' => proc{|args,conn| },
  'WHO' => proc{|args,conn| },

  'WHOIS' => proc{|args,conn|
     nick = args.last.to_s
     if target = conn.server.users.find(nick)
       conn.send_numeric(*IRC::Msg['RPL_WHOISUSER'], target.nick, target.ident, target.host, target.realname )
        #312     RPL_WHOISSERVER "<nick> <server> :<server info>"
        #313     RPL_WHOISOPERATOR "<nick> :is an IRC operator"
        #317     RPL_WHOISIDLE "<nick> <integer> :seconds idle"
        #319     RPL_WHOISCHANNELS "<nick> :{[@|+]<channel><space>}"
       conn.send_numeric(*IRC::Msg['RPL_ENDOFWHOIS'], nick)
     else
       conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], nick)
     end
   },

  'WHOWAS' => proc{|args,conn| },

  'KILL' => proc{|args,conn|
    target = conn.server.users.find(args[0])
    if args.size < 2
      conn.send_numeric(*IRC::Msg['ERR_NEEDMOREPARAMS'], 'KILL')
    elsif !conn.opered
      conn.send_numeric(*IRC::Msg['ERR_NOPRIVILEGES'])
    elsif target
      target.kill(conn, "Killed (#{conn.nick} (#{args[1]}))")
    else
      conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], args[0])
    end
  },

  'PING' => proc{|args,conn|
    conn.send_reply(conn.server.name, :pong, conn.server.name)
  },
  'PONG' => proc{|args,conn|
    # do nothing
  },

  'ERROR' => proc{|args,conn| },

  'AWAY' => proc{|args,conn|
    conn.away = args[0]
    conn.send_numeric(*IRC::Msg[args.empty? ? 'RPL_UNAWAY':'RPL_NOWAWAY'])
  },

  'REHASH'  => proc{|args,conn| },
  'DIE'     => proc{|args,conn| },
  'RESTART' => proc{|args,conn| },
  'SUMMON'  => proc{|args,conn| },
  'USERS'   => proc{|args,conn| },
  'WALLOPS' => proc{|args,conn| },

  'USERHOST' => proc{|args,conn|
    target = conn.server.users.find(args[0])
    if target
      conn.send_numeric(*IRC::Msg['RPL_USERHOST'],
                        "#{target.nick}=+#{target.ident}@#{target.ip}")
    else
      conn.send_numeric(*IRC::Msg['ERR_NOSUCHNICK'], args[0])
    end
  },

  'ISON' => proc{|args,conn| },
}


require 'socket'

module IRC
  class Channel
    attr_reader :name, :users
    attr_reader :owners, :protecteds, :ops, :halfops, :voices
    attr_reader :bans, :invex, :excepts
    attr_reader :modes, :mode_timestamp
    attr_reader :topic, :topic_timestamp
    attr_accessor :topic_author
    
    def initialize(name)
      @name = name
      @users, @owners, @protecteds = [], [], []
      @ops, @halfops, @voices = [], [], []
      @bans, @invex, @excepts = [], [], []
      @modes, @mode_timestamp = 'ns', Time.now
    end
    
    def send_to_all(*args)
      @users.each{|user| user.send_reply *args }
    end

    def send_numeric_to_all(*args)
      @users.each{|user| user.send_numeric *args }
    end
    
    def send_to_all_except(nontarget, *args)
      @users.each{|user| user.send_reply *args if user != nontarget }
    end
    
    def modes=(modes)
      @modes = modes; @modes_timestamp = Time.now
    end
    
    def topic=(topic)
      @topic = topic; @topic_timestamp = Time.now
    end
    
    def message(sender, message)
      send_to_all_except(sender, sender.path, :privmsg, @name, ':' + message)
    end

    def notice(sender, message)
      send_to_all_except(sender, sender.path, :notice, @name, ':' + message)
    end
    
    def join(client)
      @ops << client if empty?
      @users << client
      send_to_all(client.path, :join, @name)
    end
    
    def part(client, message='Leaving')
      send_to_all(client.path, :part, @name, message)
      remove client
    end
    
    def kick(client, kicker, reason=nil)
      send_to_all(kicker, :kick, @name, client.nick, reason)
      remove client
    end
    
    def remove client
      [@users, @owners, @protecteds, @ops, @halfops, @voices].each do |list|
        list.delete client
      end
    end
    
    def empty?
      @users.empty?
    end
    
    def set_topic(topic, author)
      @topic, @topic_timestamp = topic, Time.now
      @topic_author = author.nick
      send_to_all(author, :topic, @name, topic)

      send_numeric_to_all(*IRC::Msg['RPL_TOPIC'], @name, @topic)
      send_numeric_to_all(*IRC::Msg['RPL_TOPICWHOTIME'], @name, @topic_author, @topic_timestamp.to_i)
    end
    
    def has_mode? mode
      @modes.include? mode
    end
    def has_any_mode? modes
      @modes.split('').select {|mode| has_mode?(mode) }.any?
    end
    
  end

  class Client
    attr_accessor :opered, :away, :created_at, :modified_at, :ident, :realname
    attr_reader :nick, :addr, :ip, :host, :dead, :umodes
    attr_reader :server, :conn, :cmd_table

    def initialize(server, conn)
      @nick, @umodes = '*', ''
      @protocols, @watch, @silence = [], [], []
      @created_at, @modified_at = Time.now, Time.now
      @port, @ip = Socket.unpack_sockaddr_in(conn.get_peername)
      @host = @ip
      @cmd_table = CommandProc_Table.dup

      @conn, @server = conn, server
      @server.clients << self
      post_init
    end

    def post_init
      send_reply(@server.name, :notice, 'AUTH', '*** Looking up your hostname...')
      send_reply(@server.name, :notice, 'AUTH', '*** Found your hostname')
    end

    def path; "#{@nick}!#{@ident}@#{@host}"; end
    def to_s; path; end
    def has_umode?(umode); @umodes.include?(umode); end
    def has_any_umode?(umodes)
      umodes.chars.select{|umode| has_umode?(umode) }.any?
    end
    def is_registered?; @nick != '*' && @ident; end

    def is_not_registered?(command)
      if !is_registered? && !['user', 'nick', 'quit', 'pong'].include?(command)
        send_numeric(*IRC::Msg['ERR_NOTREGISTERED'])
      end
    end

    def check_registration
      return unless is_registered?
      IRC.send_welcome_flood(self)
      IRC.change_umode(self, '+iwx')
      if channel = $config['welcome_channel']
        join_channel(channel)
        send_numeric(*IRC::Msg['RPL_INFO'], "------------")
        send_numeric(*IRC::Msg['RPL_INFO'], "  auto-joining: #{channel}")
        send_numeric(*IRC::Msg['RPL_INFO'], "------------")
     end
    end

    def rawkill(killer, message='Client quit')
      send_reply(killer, :kill, @nick, message); close(message)
    end
    def kill(killer, reason='Client quit')
      rawkill(killer, "#{@server.name}!#{killer.host}!#{killer.nick} (#{reason})")
    end
    def skill(reason='Client quit')
      rawkill(@server.name, "#{@server.name} #{reason}")
    end

    def send_reply(from, *args)
      args = args.dup
      args.unshift(args.shift.to_s.upcase)
      args.unshift(":#{from}")  if from
      #args.push(":#{args.pop}") if args.last.to_s.include?(' ')

      conn.send_line args.join(' ')
    end
    
    def send_numeric(numeric, msg_pattern, *args)
      send_reply(@server.name, numeric, @nick, msg_pattern % args)
    end
    
    def nick=(newnick)
      if is_registered?
        send_reply(path, :nick, newnick)

        updated_users = [self]
        self.channels.each{|channel| channel.users.each{|user|
          unless updated_users.include?(user)
            user.send_reply(path, :nick, newnick)
            updated_users << user
          end
        }}
        @server.users.delete(@nick.downcase)
        @server.users[newnick.downcase] = self
        @nick = newnick
      else
        @nick = newnick
        @server.users[@nick.downcase] = self
        check_registration
      end
    end
    
    def join_channel(name)
      @cmd_table['JOIN'].call([name], self)
    end
    
    def channels
      @server.channels.values.select{|channel| channel.users.include?(self) }
    end

    # called by connection
    def close(reason)
      return if @dead
      @server.log_nick(@nick, "User disconnected (#{reason}).")
      
      updated_users = [self]
      self.channels.each do |channel|
        channel.users.each do |user|
          next if updated_users.include? user
          user.send_reply(path, :quit, reason)
          updated_users << user
        end
        channel.users.delete self
      end
      @dead = true
      send_reply(nil, :error, "Closing Link: #{@nick}[#{@ip}] (#{reason})")
      @server.remove_client(self)
    end

    def process_line(line)
      #p line if @server.debug
      @modified_at = Time.now

      # Parse as per the RFC
      raw_parts = line.chomp.split ' :', 2
      args = raw_parts.shift.split ' '
      args << raw_parts.first if raw_parts.any?
      command = args.shift.downcase

      @server.log_nick(@nick, [command, args].inspect) unless ['pong', 'ping'].include?(command)
      #p [command, @cmd_table[command]]

      return if is_not_registered?(command)

      if (cmd_proc = @cmd_table[command.upcase]) && cmd_proc.respond_to?(:call)
        cmd_proc.call(args, self)
        #cmd_proc.call(args, self, @conn, @server)
      else
        send_numeric(*IRC::Msg['ERR_UNKNOWNCOMMAND'], command.upcase)
      end

    rescue => ex
      puts "RESCUE: Server-side #{ex.class}: #{ex.message}"
      puts ex.class, ex.message, ex.backtrace
      skill "Server-side= ERROR Client"
    end
  end
end # IRC


#
# begin eventmachine code
#
require 'eventmachine'
module IRC
  class Connection < EM::Connection
    attr_reader :client

    def initialize(server)
      @client = Client.new(server, self)
      @buffer = ''
    end

    def post_init
      @port, @ip = Socket.unpack_sockaddr_in get_peername
      puts "Connected to #{@ip}:#{@port}"

      # process_line tick
      @tick = proc{
        if @buffer.include?("\n")
          receive_line @buffer.slice!(0, @buffer.index("\n")+1).chomp
          EM.next_tick(&@tick) if @buffer.include?("\n")
        end
      }
    end

    def receive_data data
      @buffer += data
      @tick.call
    end

    def receive_data_blocking data
      @buffer += data
      while @buffer.include?("\n")
        receive_line @buffer.slice!(0, @buffer.index("\n")+1).chomp
      end
    end

    def receive_line(line)
      @client.process_line(line)
    end

    def send_line(line)
      send_data( "#{line.gsub("\n", '')}\n" )
    end

    def unbind
      close('Client disconnected')
      puts "Connection closed to #{@ip}:#{@port}"
      super
    end
   
    def close(reason='Client quit')
      @client.close(reason); close_connection
    end
  end
end
#
# end eventmachine code
#


module IRC
  module Helpers

    def send_welcome_flood(client)
      client.send_numeric(*IRC::Msg['RPL_WELCOME'], $config['network_name'])
      client.send_numeric(*IRC::Msg['RPL_YOURHOST'], client.server.name, 'em-ircd.rb')
      client.send_numeric(*IRC::Msg['RPL_CREATED'], 'Tue Jun 23 2010 at 10:00:01 EST')
      client.send_numeric(*IRC::Msg['RPL_MYINFO'], client.server.name, 'em-irc.rb', '.', '.')
      client.cmd_table['VERSION'].call([], client)
      client.cmd_table['LUSERS'].call([], client)
      client.cmd_table['MOTD'].call([], client)
    end

    def validate_nick(nick)
      nick =~ /^[a-zA-Z\[\]_|`^][a-zA-Z0-9\[\]_|`^]{0,#{($config['max_nick_length'].to_i-1)||23}}$/
    end
    def validate_chan(channel)
      channel =~ /^\#[a-zA-Z0-9`~!@\#$%^&*\(\)\'";|}{\]\[.<>?]{0,#{($config['max_channel_length'].to_i-2)||23}}$/
    end
    
    def prefix_for(channel, whois=false)
      prefix = ''
      prefix << '~' if channel.owners.include? self
      prefix << '&' if channel.protecteds.include? self
      prefix << '@' if channel.ops.include? self
      prefix << '%' if channel.halfops.include? self
      prefix << '+' if channel.voices.include? self
      prefix
    end

    def kicked_from(target, channel, kicker, reason=nil)
      channel.kick(target, kicker, reason)
    end

    def is_on(channel, client)
      channel.users.include?(client)
    end
    def is_voice_on(channel, client)
      channel.voices.include?(client)
    end
    def is_halfop_on(channel, client)
      channel.halfops.include?(client)
    end
    def is_op_on(channel, client)
      channel.ops.include?(client)
    end
    def is_protected_on(channel, client)
      channel.protecteds.include?(client)
    end
    def is_owner_on(channel, client)
      channel.owners.include?(client)
    end
    def is_voice_or_better_on(channel, client)
      is_voice_on(channel, client) || is_halfop_or_better_on(channel, client)
    end
    def is_halfop_or_better_on(channel, client)
      is_halfop_on(channel, client) || is_op_or_better_on(channel, client)
    end
    def is_op_or_better_on(channel, client)
      is_op_on(channel, client) || is_protected_or_better_on(channel, client)
    end
    def is_protected_or_better_on(channel, client)
      is_protected_on(channel, client) || is_owner_on(channel, client)
    end
    def is_owner_or_better_on(channel, client)
      is_owner_on(channel, client)
    end
    

    def change_umode(client, changes_str, params=[])
      valid = 'oOaANCdghipqrstvwxzBGHRSTVW'
      str = IRC.parse_mode_string(changes_str, valid) do |add, char|
        next false unless valid.include? char
        if client.umodes.include?(char) ^ !add
          next false # Already set
        elsif add
          client.umodes << char
        else
          client.umodes = client.umodes.delete char
        end
        true
      end
      client.send_reply(client.path, :mode, @nick, *str) if str.any?
      str
    end

    def change_chmode(conn, channel, changes_str, params=[])
      valid = 'vhoaqbceIfijklmnprstzACGMKLNOQRSTVu'
      str = IRC.parse_mode_string(changes_str, valid) do |add, char|
        if 'vhoaq'.include? char
          list = case char
            when 'q'; channel.owners
            when 'a'; channel.protecteds
            when 'o'; channel.ops
            when 'h'; channel.halfops
            when 'v'; channel.voices
          end
          
          param = params.shift
          next false unless param
          param.downcase!

          param = channel.users.find {|u| u.nick.downcase == param }
          next false unless param
          next false if list.include?(param) ^ !add
          add ? (list << param) : list.delete(param)
          next param.nick
          
        elsif 'beI'.include? char # TODO: Allow listing
          list = case char
            when 'b'; channel.bans
            when 'e'; channel.excepts
            when 'I'; channel.invex
          end
          
          param = params.shift
          next false unless param
          next false if list.include?(param) ^ !add
          add ? (list << param) : list.delete(param)
          next param
          
        # Already set
        elsif channel.modes.include?(char) ^ !add
          params.shift if 'fjklL'.include? char
          next false
        elsif add
          params.shift if 'fjklL'.include? char
          channel.modes << char
        else
          params.shift if 'fjklL'.include? char
          channel.modes = channel.modes.delete char
        end
        true
      end
      channel.send_to_all(conn.path, :mode, channel.name, *str) if str.any?
      str
    end

    def parse_mode_string(mode_str, valid_modes)
      set, results, args = true, [], []
      mode_str.each_char do |mode_chr|
        if mode_chr == '+'
          set = true
        elsif mode_chr == '-'
          set = false
        else
          ret = valid_modes.include?(mode_chr) && yield(set, mode_chr)
          next unless ret
          results << [set, mode_chr]
          args << ret unless ret == true
        end
      end
      mode_str, set = '', nil
      results.each do |(setter, mode)|
        if setter != set
          mode_str << (setter ? '+' : '-'); set = setter
        end
        mode_str << mode
      end
      args.unshift(mode_str); args
    end

  end
  extend Helpers
end

module IRC
  Users    = {}
  Channels = {}

  def Users.remove_client(nick)
    Users.delete nick
  end

  def Channels.remove_channel(channel)
    Channels.delete channel
  end

  def Users.find(nick)
    return nick if nick.is_a? IRC::Client
    self[nick.downcase]
  end
  
  def Channels.find(name)
    return name if name.is_a? IRC::Channel
    self[name.downcase]
  end

  def Channels.find_or_create(name)
    return name if name.is_a? IRC::Channel
    self[name.downcase] ||= IRC::Channel.new(name)
  end
end

module IRC
  class Server
    attr_accessor :debug, :name, :running
    attr_reader :clients, :users, :channels

    def initialize(name=nil, users={}, channels={})
      @name, @clients = name, []
      @users, @channels = users, channels
      @debug, @running = true, false
    end

    def log msg
      puts "[#{Time.new.ctime}] #{msg}"
    end

    def log_nick nick, msg
      log "#{@host}:#{@port} #{nick}\t#{msg}"
    end

    def remove_client(client)
      Users.remove_client(client.nick.downcase) if client.is_registered?
      @clients.delete(client)
    end
    
    def destroy_channel(channel, reason='OM NOM NOM')
      channel.users.each{|user| IRC.kicked_from(user, channel, @name, reason) }
      Channels.remove_channel(channel.name.downcase)
    end
  end

  DefaultConfig = {
    'network_name' => 'em-ircd.testnet',
    'listen' => [
      {'interface' => '0.0.0.0', 'port' => '6667' },
      #{'interface' => '0.0.0.0', 'port' => '7070', 'ssl' => 'on' },
    ],
    'opers' => [],
    'max_nick_length' => 24,
    'max_channel_length' => 24,
    'oper_channel' => '#loop',
    'welcome_channel' => '#welcome',
  }
end
