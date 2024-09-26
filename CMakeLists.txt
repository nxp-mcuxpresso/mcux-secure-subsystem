
if (CONFIG_MCUX_COMPONENT_middleware.secure-subsystem)
    mcux_add_source(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        SOURCES src/sscp/fsl_sss_sscp.c
		        inc/fsl_sss_config.h
		        inc/fsl_sss_config.h
		        inc/fsl_sss_sscp.h
		        inc/fsl_sscp.h
		        inc/fsl_sscp_commands.h
		        inc/fsl_sscp_config.h
		        inc/fsl_sss_sscp_config.h
                inc/fsl_sss_api.h
    )
    
    mcux_add_include(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        INCLUDES ./inc
                 ./src/sscp
    )
	
endif()

if (CONFIG_MCUX_COMPONENT_middleware.secure-subsystem.mu)
    mcux_add_source(
	    BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        SOURCES inc/fsl_sscp_mu.h
                src/sscp/fsl_sscp_mu.c
    )
    mcux_add_include(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        INCLUDES ./inc
                 ./src/sscp
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.secure-subsystem.elemu)
    mcux_add_source(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        SOURCES inc/elemu/fsl_sss_config_elemu.h
                inc/elemu/fsl_sscp_config_elemu.h
                src/sscp/fsl_sss_mgmt.c
                inc/fsl_sss_mgmt.h
    )
    mcux_add_include(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        INCLUDES inc
                 inc/elemu
                 src/sscp
    )
	
	mcux_add_configuration(
	 TOOLCHAINS armgcc
     CC  "-DSSS_CONFIG_FILE=\\\"fsl_sss_config_elemu.h\\\" -DSSCP_CONFIG_FILE=\\\"fsl_sscp_config_elemu.h\\\""
    )
	
	mcux_add_configuration(
	 TOOLCHAINS iar
     CC  "-DSSS_CONFIG_FILE=\\\"fsl_sss_config_elemu.h\\\" -DSSCP_CONFIG_FILE=\\\"fsl_sscp_config_elemu.h\\\""
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.secure-subsystem.firmware)
    mcux_add_source(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        SOURCES firmware/ele_200_fw.h
    )
    mcux_add_include(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        INCLUDES firmware
    )
	
	mcux_add_configuration(
     CC  "-DELEMU_HAS_LOADABLE_FW"
    )
	
endif()

if (CONFIG_MCUX_COMPONENT_middleware.secure-subsystem.elemu.port_kw45_k4w1)
    mcux_add_source(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        SOURCES port/kw45_k4w1/sss_aes.c
                port/kw45_k4w1/sss_aes_cmac.c
                port/kw45_k4w1/sss_ccm.c
                port/kw45_k4w1/sss_crypto.h
                port/kw45_k4w1/sss_ecdh.c
                port/kw45_k4w1/sss_hmac_sha256.c
                port/kw45_k4w1/sss_init.c
                port/kw45_k4w1/sss_sha256.c
    )
    mcux_add_include(
        BASE_PATH ${SdkRootDirPath}/middleware/secure-subsystem
        INCLUDES port
                 port/kw45_k4w1
    )
endif()
