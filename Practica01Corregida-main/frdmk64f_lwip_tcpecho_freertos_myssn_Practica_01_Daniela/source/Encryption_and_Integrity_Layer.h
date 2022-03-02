/*
 * Encryption_and_Integrity_Layer.h
 *
 *  Created on: 6 feb. 2021
 *      Author: user
 */

#ifndef ENCRYPTION_AND_INTEGRITY_LAYER_H_
#define ENCRYPTION_AND_INTEGRITY_LAYER_H_

#include "Encryption_and_Integrity_Layer_Interface.h"
#include "Encryption_and_Integrity_Layer_Config.h"

typedef union { /*Variable para el manejo del CRC*/
	uint32_t crc32;
	uint8_t  strcrc[4];
}stCRC;

/*--------------------Functions------------------------*/

/*Initialitations*/
void Init_EncryptionAndIntegrity(); /*Initialize the basic seting for tcp conectivity and AES encription*/

/*Encryption*/
static size_t encrypt_msg(); /*Function to encrypt*/
static void decrypt_msg(uint8_t *test_string, u16_t len , stCRC *CRC); /*Function to decrypt*/

/*TCP/IP*/
int server_create(void *arg); /*Creación de server*/
err_t server_accept();/*aceptación del servicor creado*/
void close(void); /*Cierre de conexión*/

/*send/receive*/
void Echo_TCP(void); /*Función para recibir mensajes, desnecrytación obtención de CRC renecritación y re-enviín de emnsaje,
basicamente es el echo*/

/*CRC*/
static uint32_t calculate_CRC(uint8_t padded_msg[],size_t padded_len); /*calculo de CRC*/
static void concatenate_strToSend_CRC(uint8_t *padded_msg,size_t Encrypted_text_size, stCRC *checksum32); /*concatena el ensaje encryptado con el CRC antes de mandarlo*/
static void InitCrc32(CRC_Type *base, uint32_t seed);/*inicializa CRC32*/
static stCRC get_CRC(uint8_t *data); /*saca el CRC del mensaje recibido*/

/*funciones que se usan como auxiliares en otras funciones*/
void messageBody(uint8_t *padded_msg, size_t test_string_len); /*obtención del cuerpo del mensaje separando del CRC*/
static void substr(uint8_t *cad,uint8_t *sub,size_t ini,size_t fin);/*función para auxiliar a la función de obtencion del CRC del
menjsaje recibido*/

/**/

#endif /* ENCRYPTION_AND_INTEGRITY_LAYER_H_ */
