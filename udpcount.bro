########################################################################################################################
# Esse modulo esta conrtando por endereço IP, e dizer que tudo o que esta sendo enviado desde o atacante é cortado
# com a inserção do set no conjunto de endereços, é evitado um flooding desde os sensores ao controlador,
# já que é enviado uma mensagen só quando o limiar da media é ultrapassado. 
# >>Melhora 1: Agora se deveria melhorar botando um timer para limpiar a tabela de bloqueio
# >>Melhora 2: Obter a media inicial, agora estão se botando 30 pacotes/s só de teste, procurar artigo onde se fale isto
########################################################################################################################

@load martin/flooding

module UDPCount;


event udp_request(u: connection) {
  
     flood_detection(u);

}



