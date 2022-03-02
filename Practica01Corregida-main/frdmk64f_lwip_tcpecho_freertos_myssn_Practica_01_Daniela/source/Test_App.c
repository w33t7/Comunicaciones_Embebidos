/*
 * Test_App.c
 *
 *  Created on: 20 feb. 2022
 *      Author: user
 */


#include "Encryption_and_Integrity_Layer.h"

void Test_App(void){/*interface con usuario para interactuar con la capa de encripción y CRC (Server)*/

	/*Asegurar la conexion*/

	err_t err;
	int resp = server_create(1); /*Creación de servidor*/
	if(resp==NULL){
		PRINTF("Aca");
	}else{
		PRINTF("Esperando conexión ...\n");
		err = server_accept(); /*Conexión con cliente*/
		if (err == ERR_OK){
			PRINTF("Presione SW3 para modo echo  \n");
			LED_RED_ON();
			while(1){
			if(SWpress3){
				SWpress3=false;
				Echo();
			}
			}
		}
		else{
			close();
		}

	}



}

void Echo(void){/*Entra al modo echo*/

	PRINTF("Echo ...\n");
	LED_RED_OFF();
	Echo_TCP();

}
