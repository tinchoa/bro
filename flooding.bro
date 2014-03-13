########################################################################################################################
# Esse modulo esta conrtando por endereço IP, e dizer que tudo o que esta sendo enviado desde o atacante é cortado
# com a inserção do set no conjunto de endereços, é evitado um flooding desde os sensores ao controlador,
# já que é enviado uma mensagen só quando o limiar da media é ultrapassado. 
# >>Melhora 1: Agora se deveria melhorar botando um timer para limpiar a tabela de bloqueio
# >>Melhora 2: Obter a media inicial, agora estão se botando 30 pacotes/s só de teste, procurar artigo onde se fale isto
########################################################################################################################

@load martin/block
@load martin/packets_count



	global udpreq=0;
	global udprep=0;

	global j=0; #indice de pacotes
	global i=0;#indice de periodos
	global flag =0; #bandera de inicio
	global initial=0; #bandera de inicio inicio

	global inicial:time;
	global primero:time;
	global tiempo:interval;

	global UDPCounters: vector of int; #number of syn packets for each address

	global index: vector of int; # vector de paquetes SYN por intervalo de tiempo
	global address : vector of addr; #vector onde estão salvados os endereços
	global periods: vector of int;#vector de periodos
	global times: vector of time;#vector de tiempos para ver la frecuencia

	global tabla: table [int,addr] of int; #diccionario donde llevo el periodo, la direccion y un flag para anunciar que ya paso la media y son almacenados en un int q es la cant de pacotes

	global time_table:table [addr] of time;

	global possible_attack :vector of int; #flag para indicar que ya fue enviada a mensagem

	global pacotes: count; #pacotes recibidos

	global ti:int; #indice para llevar los tiempos

	#global u: vector of double; # vector de medias esto en principio lo deberia tomar de algun lado
	#global alarme: count; #contador de cuantas veces voy a pasar el limite
	#global alpha = 0.2; #este es el valor en porcentaje sobre la media para indicar el comportamiento anormal
	#global betta= 0.75; #Exponential Weight Moving Average (EWMA)
	#global ture= 0;

	global test_flag:int;
	global messages_sent=0;

	global flags: set [addr] = set();# para ver si ya mande msg

	const number_trigger = 30 &redef;
	const time_period =10 sec &redef;


########################create log
#export {
#        redef enum Log::ID += { LOG };
#        type Info: record {
                ## Timestamp when the syslog message was seen.
#               ts:        time            &log;
                ## The connection's 4-tuple of endpoint addresses/ports.
#                id:        conn_id         &log;
#       };
# }

#redef record connection += {
#        test: Info &optional;
# };

###############################################


event bro_init() &priority=5
	{
	udpreq=0;
	udprep=0;
	flag=0;
	j=0;
	ti=0;
	possible_attack[0]=0;
	pacotes=0;
    #Log::create_stream(UDPCount::LOG, [$columns=Info]);
	print fmt("Initiating...");
	}


function flood_detection(u: connection){
    local srcIP = u$id$orig_h;
    local destIP = u$id$resp_h;
    local dstPort =u$id$resp_p;
	local a:int; #indice para enviar a la funcion de busqueda

	local number:int;
	local start_time=u$start_time;


   # local rec: UDPCount::Info = [$ts=network_time(), $id=u$id];
   #u$test = rec;
    ++pacotes;
	


	if (initial==0) #flag para tomar el tiempo del experimento
			{
			initial=1;
			primero=current_time();
			}
	if (flag==0)#primer pacote del periodo??
			{
			address[0]=srcIP;#inicio el vector de endereços
			flag=1;
			inicial=current_time();#tomo el tiempo inicial de llegada del pacote
			++j;#contador de pacotes
			time_table[srcIP]=start_time;#tomo el tiempo de llegada de cada paquete
			times[ti]=start_time;
			++ti;#incremento el contador
			}
	else  #si no es el primero voy guardando os endereços associados aos paquetes
			{
			address[j]=srcIP;
			++j;#contador de pacotes
			time_table[srcIP]=start_time;#tomo el tiempo de llegada de cada paquete
			times[ti]=start_time;
			++ti;#incremento el contador
			}

	tiempo = (current_time()-inicial);#tomo el tiempo inicial para medir

	if (tiempo <= (time_period))#periodo de duracion 10seg
			{
			periods[i]=j;#salvo el numero de periodo
			}
	else
			{
			++i;#incremento el numero de periodos
			for (a in address)
				{
				number=packets_count(address, address[a]);#funcion que busca la cantidad de veces que tengo un endereço en un arreglo
				#print fmt ("%d",number);
				tabla[i,address[a]] = number;#genero mi tabla(diccionario)
		
				if (number >= number_trigger )
					{
					 if (address[a] !in flags)
    					{
    					print fmt ("Address %s Number %d",address[a],number);
    					add flags[address[a]];
    					block_packets(address[a],destIP,dstPort);
			        	#Log::write(UDPCount::LOG, rec);
    					}
    				}
				}

			flag=0; #flag de inicio 
			j=0;# contador de pacotes por periodo
			}
}
 


  




event bro_done()
	{
	local k:int;

	print fmt ("%s",tabla);

	#print fmt ("end");
	#print fmt ("Tabla de tiempos :%s",time_table);
	#print fmt ("Messages sent: %d",messages_sent);
	print fmt ("Packet Received : %d",pacotes);


	}


