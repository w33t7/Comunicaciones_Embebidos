################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lwip/src/core/altcp.c \
../lwip/src/core/altcp_alloc.c \
../lwip/src/core/altcp_tcp.c \
../lwip/src/core/def.c \
../lwip/src/core/dns.c \
../lwip/src/core/inet_chksum.c \
../lwip/src/core/init.c \
../lwip/src/core/ip.c \
../lwip/src/core/mem.c \
../lwip/src/core/memp.c \
../lwip/src/core/netif.c \
../lwip/src/core/pbuf.c \
../lwip/src/core/raw.c \
../lwip/src/core/stats.c \
../lwip/src/core/sys.c \
../lwip/src/core/tcp.c \
../lwip/src/core/tcp_in.c \
../lwip/src/core/tcp_out.c \
../lwip/src/core/timeouts.c \
../lwip/src/core/udp.c 

OBJS += \
./lwip/src/core/altcp.o \
./lwip/src/core/altcp_alloc.o \
./lwip/src/core/altcp_tcp.o \
./lwip/src/core/def.o \
./lwip/src/core/dns.o \
./lwip/src/core/inet_chksum.o \
./lwip/src/core/init.o \
./lwip/src/core/ip.o \
./lwip/src/core/mem.o \
./lwip/src/core/memp.o \
./lwip/src/core/netif.o \
./lwip/src/core/pbuf.o \
./lwip/src/core/raw.o \
./lwip/src/core/stats.o \
./lwip/src/core/sys.o \
./lwip/src/core/tcp.o \
./lwip/src/core/tcp_in.o \
./lwip/src/core/tcp_out.o \
./lwip/src/core/timeouts.o \
./lwip/src/core/udp.o 

C_DEPS += \
./lwip/src/core/altcp.d \
./lwip/src/core/altcp_alloc.d \
./lwip/src/core/altcp_tcp.d \
./lwip/src/core/def.d \
./lwip/src/core/dns.d \
./lwip/src/core/inet_chksum.d \
./lwip/src/core/init.d \
./lwip/src/core/ip.d \
./lwip/src/core/mem.d \
./lwip/src/core/memp.d \
./lwip/src/core/netif.d \
./lwip/src/core/pbuf.d \
./lwip/src/core/raw.d \
./lwip/src/core/stats.d \
./lwip/src/core/sys.d \
./lwip/src/core/tcp.d \
./lwip/src/core/tcp_in.d \
./lwip/src/core/tcp_out.d \
./lwip/src/core/timeouts.d \
./lwip/src/core/udp.d 


# Each subdirectory must supply rules for building sources it contributes
lwip/src/core/%.o: ../lwip/src/core/%.c lwip/src/core/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK64FN1M0VLL12 -DCPU_MK64FN1M0VLL12_cm4 -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DFRDM_K64F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=1 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\board" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\source" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\drivers" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\device" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\CMSIS" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\contrib\apps\tcpecho" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\port\arch" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix\arpa" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix\net" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix\sys" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\stdc" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\lwip" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\lwip\priv" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\lwip\prot" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\netif" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\netif\ppp" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\netif\ppp\polarssl" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\port" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\amazon-freertos\freertos_kernel\include" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\utilities" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\component\serial_manager" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\component\lists" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\component\uart" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include" -O0 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


