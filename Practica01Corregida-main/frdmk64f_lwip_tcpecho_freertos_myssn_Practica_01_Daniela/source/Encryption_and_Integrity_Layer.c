/*
 * Encryption_and_Integrity_Layer.c
 *
 *  Created on: 26 feb. 2021
 *      Author: user
 */

#include "Encryption_and_Integrity_Layer.h"

struct netconn *conn, *newconn;
uint8_t *Plain_Text;
uint8_t *Encrypted_text;
void Init_EncryptionAndIntegrity(){/*Condiciones iniciales*/

	 static struct netif netif;
	#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
	    static mem_range_t non_dma_memory[] = NON_DMA_MEMORY_ARRAY;
	#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
	    ip4_addr_t netif_ipaddr, netif_netmask, netif_gw;
	    ethernetif_config_t enet_config = {
	        .phyAddress = EXAMPLE_PHY_ADDRESS,
	        .clockName  = EXAMPLE_CLOCK_NAME,
	        .macAddress = configMAC_ADDR,
	#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
	        .non_dma_memory = non_dma_memory,
	#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
	    };

	    SYSMPU_Type *base = SYSMPU;
	    BOARD_InitPins();
	    BOARD_BootClockRUN();
	    BOARD_InitDebugConsole();

	    BOARD_InitGPIOInterrupts();
	    /* Disable SYSMPU. */
	    base->CESR &= ~SYSMPU_CESR_VLD_MASK;

	    IP4_ADDR(&netif_ipaddr, configIP_ADDR0, configIP_ADDR1, configIP_ADDR2, configIP_ADDR3);
	    IP4_ADDR(&netif_netmask, configNET_MASK0, configNET_MASK1, configNET_MASK2, configNET_MASK3);
	    IP4_ADDR(&netif_gw, configGW_ADDR0, configGW_ADDR1, configGW_ADDR2, configGW_ADDR3);

	    tcpip_init(NULL, NULL);

	    netifapi_netif_add(&netif, &netif_ipaddr, &netif_netmask, &netif_gw, &enet_config, EXAMPLE_NETIF_INIT_FN,
	                       tcpip_input);
	    netifapi_netif_set_default(&netif);
	    netifapi_netif_set_up(&netif);

	    PRINTF("\r\n************************************************\r\n");
	    PRINTF(" TCP Echo example\r\n");
	    PRINTF("************************************************\r\n");
	    PRINTF(" IPv4 Address     : %u.%u.%u.%u\r\n", ((u8_t *)&netif_ipaddr)[0], ((u8_t *)&netif_ipaddr)[1],
	           ((u8_t *)&netif_ipaddr)[2], ((u8_t *)&netif_ipaddr)[3]);
	    PRINTF(" IPv4 Subnet mask : %u.%u.%u.%u\r\n", ((u8_t *)&netif_netmask)[0], ((u8_t *)&netif_netmask)[1],
	           ((u8_t *)&netif_netmask)[2], ((u8_t *)&netif_netmask)[3]);
	    PRINTF(" IPv4 Gateway     : %u.%u.%u.%u\r\n", ((u8_t *)&netif_gw)[0], ((u8_t *)&netif_gw)[1],
	           ((u8_t *)&netif_gw)[2], ((u8_t *)&netif_gw)[3]);
	    PRINTF("************************************************\r\n");

	    /* Define the init structure for the output LED pin */
	       gpio_pin_config_t led_config = {
	           kGPIO_DigitalOutput,
	           1,
	       };

	    /* Init output LED GPIO. */
	     GPIO_PinInit(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PIN, &led_config);
	     GPIO_PinInit(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PIN, &led_config);
	     GPIO_PinInit(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PIN, &led_config);

}

/*Encryption*/
static size_t encrypt_msg(stCRC *checksum32){/*Function to encrypt*/

	struct AES_ctx ctx;
	size_t test_string_len, padded_len;
	uint8_t padded_msg[512] = {0};
	/* CRC data */
	CRC_Type *base = CRC0;

	PRINTF("\n INFO: sending data : ");
	PRINTF("%s", Plain_Text);


	AES_init_ctx_iv(&ctx, key, iv);

	test_string_len = strlen(Plain_Text);
	padded_len = test_string_len + (16 - (test_string_len%16) );
	memcpy(padded_msg, Plain_Text, test_string_len);
	/*Encriptación del mensaje*/
	AES_CBC_encrypt_buffer(&ctx, padded_msg, padded_len);
	size_t Encrypted_text_size =  strlen(padded_msg);

	PRINTF("\n INFO: encrypted message %s",padded_msg);

	/*Re calculo de CRC*/
	checksum32->crc32 = calculate_CRC(padded_msg,Encrypted_text_size);

	PRINTF("\n INFO: tc crc32 = %u ,",checksum32->crc32);
	PRINTF("crc bytes = ");
	for(int x = 0;x<4;x++){
		PRINTF("0x%x ,",checksum32->strcrc[x]);
	}
	/*info para envía : mensaje encriptado +  CRC*/
	concatenate_strToSend_CRC(&padded_msg,Encrypted_text_size, checksum32);

	Encrypted_text_size =  strlen(padded_msg);
	Encrypted_text = (uint8_t*)malloc(Encrypted_text_size*sizeof(uint8_t));
	memcpy(Encrypted_text,padded_msg,Encrypted_text_size +1 );
	//PRINTF("Encrypted: %s  \n",Encrypted_text);

	return Encrypted_text_size;


}
static void decrypt_msg(uint8_t *test_string, u16_t len , stCRC *CRC){/*Function to decrypt*/

	/* AES data */
	struct AES_ctx ctx;
	size_t test_string_len, padded_len;
	uint8_t padded_msg[512] = {0};

	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	stCRC crc;

	/* Init the AES context structure */
	AES_init_ctx_iv(&ctx, key, iv);

	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
	test_string_len = strlen(test_string);
	padded_len = test_string_len + (16 - (test_string_len%16) );
	memcpy(padded_msg, test_string, test_string_len);

	/*getting CRC from received data*/
	*CRC = get_CRC(test_string);

	/*****Getting boddy******/

	messageBody(&padded_msg,test_string_len);

	/*****Decrypted********/
	AES_CBC_decrypt_buffer(&ctx, padded_msg, len-4);


	size_t PlainText_size = strlen(padded_msg);
	Plain_Text = (uint8_t*)malloc(PlainText_size*sizeof(uint8_t));
	memcpy(Plain_Text,padded_msg,PlainText_size +1 );

	PRINTF("\n DATA : ");
	PRINTF("%s", Plain_Text);
	PRINTF("\r\n");
}

/*TCP/IP*/
int server_create(void *arg){

	LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
/* Bind connection to well known port number 7. */
#if LWIP_IPV6
	conn = netconn_new(NETCONN_TCP_IPV6);
	netconn_bind(conn, IP6_ADDR_ANY, PORT);
#else /* LWIP_IPV6 */
	conn = netconn_new(NETCONN_TCP); //socket
	netconn_bind(conn, IP_ADDR_ANY, PORT); //bign()
#endif /* LWIP_IPV6 */
LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return);

	if(conn!=NULL)
		return 1;
	else
		return 0;

}
err_t server_accept(){/*Creación de servidor*/
	err_t  err_1;
	netconn_listen(conn);
	err_1 = netconn_accept(conn, &newconn);
	return err_1;

}
void close(void){
	netconn_close(newconn);
	netconn_delete(newconn);
}

void Echo_TCP(void){
	err_t err;
	struct netbuf *buf;
	void *data;
	u16_t len;
	stCRC newCRC , OriCRC;


 		while ((err = netconn_recv(newconn, &buf)) == ERR_OK && !SWpress2) {//recv()

			do {

				netbuf_data(buf, &data, &len); /*Recibo de información*/
				LED_RED_OFF();
				LED_BLUE_ON();
				decrypt_msg(data, len,&OriCRC);/*CRC, obtención del cuerpo del mensaje y desencriptación*/
				len = encrypt_msg(&newCRC);/*Encriptación y re calculo de CRC*/
				if(OriCRC.crc32 == newCRC.crc32 ){/*Si ambos CRC coinciden se re envía el mensaje*/
					LED_BLUE_OFF();
					err = netconn_write(newconn, Encrypted_text, len, NETCONN_COPY);//envio de mensaje re-encriptado + CRC
					LED_GREEN_ON();
				}
				else{/*Si no coincide se cierra la conexión*/
					PRINTF("CRC no coincide");
					LED_RED_ON();
					close();
				}
				LED_GREEN_OFF();

#if 0
	if (err != ERR_OK) {
	printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
	}
#endif
			} while (netbuf_next(buf) >= 0);
			netbuf_delete(buf);
			}
		close();

}

void messageBody(uint8_t *padded_msg, size_t test_string_len){
	/*getting body data*/
	for(int x  = 1; x < 5;x++){
	padded_msg[test_string_len-x] = 0;
	}

}
static stCRC get_CRC(uint8_t *data){

	stCRC CRC;
	size_t fin, ini;
	fin = strlen(data) - 1 ;
	ini = fin -4 ;
	substr(data,CRC.strcrc,ini,fin);
	//PRINTF("%s\n",CRC.strcrc);
	return CRC;

}
static void substr(uint8_t *cad,uint8_t *sub,size_t ini,size_t fin){

	int ic = fin - 3,is = 0;
	for(;is<4;is++){
		sub[is] = cad[ic];
		ic++;
	}

}
static uint32_t calculate_CRC(uint8_t padded_msg[],size_t padded_len){

	/* CRC data */
	CRC_Type *base = CRC0;
	uint32_t checksum32;
	//PRINTF("\nTesting CRC32\r\n\n");

	InitCrc32(base, 0xFFFFFFFFU);
	CRC_WriteData(base, (uint8_t *)&padded_msg[0], padded_len);
	checksum32 = CRC_Get32bitResult(base);
	//PRINTF("CRC-32: 0x%08x\r\n", checksum32);

	return checksum32;

}

static void InitCrc32(CRC_Type *base, uint32_t seed)
{
    crc_config_t config;

    config.polynomial         = 0x04C11DB7U;
    config.seed               = seed;
    config.reflectIn          = true;
    config.reflectOut         = true;
    config.complementChecksum = true;
    config.crcBits            = kCrcBits32;
    config.crcResult          = kCrcFinalChecksum;

    CRC_Init(base, &config);
}
static void concatenate_strToSend_CRC(uint8_t *padded_msg,size_t Encrypted_text_size, stCRC *checksum32){

	for(int x = 0; x < 4;x++){
	padded_msg[Encrypted_text_size + x] = checksum32->strcrc[x];
	}
}
