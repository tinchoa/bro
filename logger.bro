module Martin;

global sum =0;

export {
# Create an ID for our new stream. By convention, this is
# called "LOG".
redef enum Log::ID += { LOG };

# Define the record type that will contain the data to log.
type Info: record {
	# ts: time &log;
	#id: conn_id &log;
	# service: string &log &optional;
	#missed_bytes: count &log &default=0;
	conter: count  &log &optional; 
	ts: time &log;
	#proto:        transport_proto &log;
	orig_h: addr &log; 
	orig_p: port &log;
	resp_h: addr &log;
	resp_p: port &log;
	# status: string &log &optional;
	#country: string &default="unknown";
	# ttl: count &log;
	service: string &log &optional;
	payload: string &log &optional;
};

}


# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event bro_init() &priority=5
{
# Create the stream. This adds a default filter automatically.
Log::create_stream(Martin::LOG, [$columns=Info
, $path="pep"
]);
sum=0;
print "Starting";
}

function determine_service(c: connection): string
{
local service = "";
for ( s in c$service )
{
if ( sub_bytes(s, 0, 1) != "-" )
service = service == "" ? s : cat(service, ",", s);
}

return to_lower(service);
}
 


function set_conn(c: connection, eoc: bool)
	{
	c$conn$ts=c$start_time;
	c$conn$uid=c$uid;
	c$conn$id=c$id;
	if ( c?$tunnel && |c$tunnel| > 0 )
		add c$conn$tunnel_parents[c$tunnel[|c$tunnel|-1]$uid];
	c$conn$proto=get_port_transport_proto(c$id$resp_p);
	if( |Site::local_nets| > 0 )
		{
		c$conn$local_orig=Site::is_local_addr(c$id$orig_h);
		c$conn$local_resp=Site::is_local_addr(c$id$resp_h);
		}

	if ( eoc )
		{
		if ( c$duration > 0secs )
			{
			c$conn$duration=c$duration;
			c$conn$orig_bytes=c$orig$size;
			c$conn$resp_bytes=c$resp$size;
			}
		if ( c$orig?$num_pkts )
			{
			# these are set if use_conn_size_analyzer=T
			# we can have counts in here even without duration>0
			c$conn$orig_pkts = c$orig$num_pkts;
			c$conn$orig_ip_bytes = c$orig$num_bytes_ip;
			c$conn$resp_pkts = c$resp$num_pkts;
			c$conn$resp_ip_bytes = c$resp$num_bytes_ip;
			}
		local service = determine_service(c);
		if ( service != "" )
			c$conn$service=service;
#		c$conn$conn_state=conn_state(c, get_port_transport_proto(c$id$resp_p));
		}
	}

event packet_contents(c:connection, contents:string ){
		
		local service = determine_service(c);

		sum+=1;
		Log::write(Martin::LOG, [$ts=network_time(),
			$conter= sum,
			$orig_h= c$id$orig_h,
			$orig_p= c$id$orig_p,
			$resp_p= c$id$resp_p,
			$service=service,
			$payload=contents
		 ]);
 }


