################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../amazon-freertos/freertos_kernel/event_groups.c \
../amazon-freertos/freertos_kernel/list.c \
../amazon-freertos/freertos_kernel/queue.c \
../amazon-freertos/freertos_kernel/stream_buffer.c \
../amazon-freertos/freertos_kernel/tasks.c \
../amazon-freertos/freertos_kernel/timers.c 

OBJS += \
./amazon-freertos/freertos_kernel/event_groups.o \
./amazon-freertos/freertos_kernel/list.o \
./amazon-freertos/freertos_kernel/queue.o \
./amazon-freertos/freertos_kernel/stream_buffer.o \
./amazon-freertos/freertos_kernel/tasks.o \
./amazon-freertos/freertos_kernel/timers.o 

C_DEPS += \
./amazon-freertos/freertos_kernel/event_groups.d \
./amazon-freertos/freertos_kernel/list.d \
./amazon-freertos/freertos_kernel/queue.d \
./amazon-freertos/freertos_kernel/stream_buffer.d \
./amazon-freertos/freertos_kernel/tasks.d \
./amazon-freertos/freertos_kernel/timers.d 


# Each subdirectory must supply rules for building sources it contributes
amazon-freertos/freertos_kernel/%.o: ../amazon-freertos/freertos_kernel/%.c amazon-freertos/freertos_kernel/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK64FN1M0VLL12 -DCPU_MK64FN1M0VLL12_cm4 -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DFRDM_K64F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=1 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\board" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\source" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\drivers" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\device" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\CMSIS" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\contrib\apps\tcpecho" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\port\arch" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix\arpa" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix\net" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\posix\sys" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\compat\stdc" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\lwip" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\lwip\priv" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\lwip\prot" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\netif" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\netif\ppp" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include\netif\ppp\polarssl" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\port" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\amazon-freertos\freertos_kernel\include" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\utilities" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\component\serial_manager" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\component\lists" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\component\uart" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src" -I"C:\Workspace\Especialidad\Sistemas de Comunicaciones\Practica1\Practica01Corregida-main\frdmk64f_lwip_tcpecho_freertos_myssn_Practica_01_Corregida\lwip\src\include" -O0 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


