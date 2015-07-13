##This Script log every single packet that appear on the network interface
## the logger fields are counter

module Martin;

global sum =0;

export {
# Create an ID for our new stream. By convention, this is
# called "LOG".
redef enum Log::ID += { LOG };

# Define the record type that will contain the data to log.
type Info: record {
	conter: count  &log &optional;  #counter of packet seeing since the script start 
	ts: time &log; #timestamp
	proto:        transport_proto &log; # transport protocol identification
	orig_h: addr &log; #IP address source
	orig_p: port &log; #IP port source
	resp_h: addr &log; #IP address destination
	resp_p: port &log; #IP port source 
	service: string &log &optional; #type of ethernet service
	payload: string &log &optional; #payload of packet
};

}

# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event bro_init() &priority=5 {
	# Create the stream. This adds a default filter automatically.
	Log::create_stream(Martin::LOG, [$columns=Info
	, $path="pep" #name of the file
	]);
	sum=0;
	print "Starting";
 }

function determine_service(c: connection): string {
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
		}
	}

event packet_contents(c:connection, contents:string ){
		
		local service = determine_service(c);
		local proto=get_port_transport_proto(c$id$resp_p);

		sum+=1;
		Log::write(Martin::LOG, [$ts=network_time(),
			$conter= sum,
			$orig_h= c$id$orig_h,
			$orig_p= c$id$orig_p,
			$resp_p= c$id$resp_p,
			$proto = proto,
			$resp_h= c$id$resp_h,
			$service=service,
			$payload=contents
		 ]);
 }


