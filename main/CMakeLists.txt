if(CONFIG_BT_ENABLED)
    set(bledir "ble")
endif()

if(CONFIG_ETH_USE_OPENETH)
    set(qemudir "qemu")
    if (CONFIG_HAS_CAMERA)
        set(qemu_display_file ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
    endif()
endif()

if (CONFIG_BOARD_TYPE_JADE_ANY)
    list(APPEND logo_files ${PROJECT_DIR}/logo/splash.bin.gz ${PROJECT_DIR}/logo/ce.bin.gz ${PROJECT_DIR}/logo/fcc.bin.gz ${PROJECT_DIR}/logo/weee.bin.gz)
    if (CONFIG_BOARD_TYPE_JADE_V1_1 OR CONFIG_BOARD_TYPE_JADE_V2_ANY)
        list(APPEND logo_files ${PROJECT_DIR}/logo/telec.bin.gz)
    endif()
endif()

if (CONFIG_DISPLAY_HEIGHT GREATER_EQUAL 170)
    list(APPEND logo_files ${PROJECT_DIR}/logo/statusbar_large.bin.gz)
else()
    list(APPEND logo_files ${PROJECT_DIR}/logo/statusbar_small.bin.gz)
endif()

if (CONFIG_IDF_TARGET_ESP32S3)
    set(usbdir "usbhmsc")
endif()

if(CONFIG_AMALGAMATED_BUILD)
    set(wallydir "${PROJECT_DIR}/components/libwally-core")
    list(APPEND wallydirs "${wallydir}" "${wallydir}/upstream" "${wallydir}/upstream/src" "${wallydir}/upstream/src/ccan")
    set(secpdir "${wallydir}/upstream/src/secp256k1/include")
endif()

if(CONFIG_LOG_WIFI)
    list(APPEND extra_priv_requires "esp_wifi")
endif()

if(CONFIG_TREZOR_USB_HID AND CONFIG_DEBUG_MODE)
    message(FATAL_ERROR "CONFIG_TREZOR_USB_HID must not be combined with CONFIG_DEBUG_MODE")
endif()

if(CONFIG_TREZOR_USB_HID AND (CONFIG_TINYUSB_CDC_ENABLED OR CONFIG_JADE_USE_USB_JTAG_SERIAL))
    message(FATAL_ERROR "CONFIG_TREZOR_USB_HID must not be combined with Jade USB serial/RPC transports")
endif()

find_program(HOST_CC NAMES cc clang gcc)

idf_component_register(SRC_DIRS "."
                                "attestation"
                                "chains"
                                "chains/bitcoin"
                                "chains/ethereum"
                                "chains/tron"
                                "crypto"
                                "fonts"
                                "process"
                                "protocols/trezor"
                                "protocols/trezor/bitcoin"
                                "protocols/trezor/ethereum"
                                "wallet_core"
                                "utils"
                                "ui"
                                "${bledir}"
                                "${qemudir}"
                                "${usbdir}"
        PRIV_INCLUDE_DIRS "."
                          "attestation"
                          "wallet_core"
                          "${bledir}"
                          "${qemudir}"
                          "${usbdir}"
                          "${wallydirs}"
                          "${secpdir}"
        PRIV_REQUIRES assets libwally-core libsodium esp32-rotary-encoder esp32-quirc bootloader_support app_update nvs_flash bt autogenlang cbor esp_netif esp32_bsdiff esp32_deflate nghttp esp32_bc-ur driver mbedtls http_parser esp_hw_support efuse esp_eth esp_http_server esp_lcd usb vfs app_trace spi_flash google-otpauth-migrate ${extra_priv_requires}
        EMBED_FILES ${PROJECT_DIR}/pinserver_public_key.pub ${logo_files} ${qemu_display_file})

if(CONFIG_ETH_USE_OPENETH)
    if (CONFIG_HAS_CAMERA)
        add_custom_command(OUTPUT ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz
             COMMAND sed -e "s/DISPLAY_WIDTH/${CONFIG_DISPLAY_WIDTH}/g" -e "s/DISPLAY_HEIGHT/${CONFIG_DISPLAY_HEIGHT}/g" ${PROJECT_DIR}/main/qemu/display.html | gzip -k -9 -c > ${PROJECT_DIR}/build/display.html.gz
             COMMAND gzip -k -9 -c ${PROJECT_DIR}/main/qemu/${CONFIG_DISPLAY_QEMU_IMAGE}.png > ${PROJECT_DIR}/build/jade.png.gz
             DEPENDS ${PROJECT_DIR}/main/qemu/display.html ${PROJECT_DIR}/main/qemu/jade.png
             VERBATIM)

        add_custom_target(gen_gz_files
                          DEPENDS ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)

        add_dependencies(${COMPONENT_LIB} gen_gz_files)

        set_property(DIRECTORY "${COMPONENT_DIR}" APPEND PROPERTY
                ADDITIONAL_MAKE_CLEAN_FILES ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
        list(APPEND link_options "-Wl,--wrap=esp_camera_init")
        list(APPEND link_options "-Wl,--wrap=esp_camera_deinit")
        list(APPEND link_options "-Wl,--wrap=esp_camera_fb_get")
        list(APPEND link_options "-Wl,--wrap=esp_camera_fb_return")
    endif()
endif()

if(CONFIG_AMALGAMATED_BUILD)
    add_compile_definitions(AMALGAMATED_BUILD=1)
endif()

target_link_libraries(${COMPONENT_TARGET} "-u custom_app_desc")
list(APPEND link_options "-Wl,--wrap=abort")
idf_build_set_property(LINK_OPTIONS "${link_options}" APPEND)

target_compile_options(${COMPONENT_LIB} PRIVATE -Werror=unused-result)

if(HOST_CC)
    set(eth_tron_address_gate_bin ${CMAKE_BINARY_DIR}/eth_tron_address_gate)
    set(eth_tron_address_gate_stamp ${CMAKE_BINARY_DIR}/eth_tron_address_gate.stamp)
    set(wallet_core_public_node_gate_bin ${CMAKE_BINARY_DIR}/wallet_core_public_node_gate)
    set(wallet_core_public_node_gate_stamp ${CMAKE_BINARY_DIR}/wallet_core_public_node_gate.stamp)
    add_custom_command(OUTPUT ${eth_tron_address_gate_stamp}
        COMMAND ${HOST_CC} -std=c11 -Wall -Wextra -Werror
            -DTREZOR_ETHEREUM_DEFINITIONS_HOST_TEST
            -I${COMPONENT_DIR}
            -I${COMPONENT_DIR}/test/host_shims
            -I${PROJECT_DIR}/components/libwally-core/upstream/include
            ${COMPONENT_DIR}/test/eth_tron_address_gate.c
            ${COMPONENT_DIR}/chains/authorization.c
            ${COMPONENT_DIR}/chains/confirm_summary.c
            ${COMPONENT_DIR}/chains/evm_abi.c
            ${COMPONENT_DIR}/crypto/keccak256.c
            ${COMPONENT_DIR}/chains/bitcoin/address.c
            ${COMPONENT_DIR}/chains/bitcoin/confirm.c
            ${COMPONENT_DIR}/chains/bitcoin/path.c
            ${COMPONENT_DIR}/chains/bitcoin/wallet.c
            ${COMPONENT_DIR}/chains/ethereum/address.c
            ${COMPONENT_DIR}/chains/ethereum/authorize.c
            ${COMPONENT_DIR}/chains/ethereum/confirm.c
            ${COMPONENT_DIR}/chains/ethereum/digest.c
            ${COMPONENT_DIR}/chains/ethereum/path.c
            ${COMPONENT_DIR}/chains/ethereum/sign.c
            ${COMPONENT_DIR}/chains/ethereum/tx.c
            ${COMPONENT_DIR}/chains/ethereum/tx_request.c
            ${COMPONENT_DIR}/chains/ethereum/wallet.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/protocol.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/policy.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/requests.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/signing_state.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/prev_tx_verifier.c
            ${COMPONENT_DIR}/protocols/trezor/dispatcher.c
            ${COMPONENT_DIR}/protocols/trezor/ethereum/protocol.c
            ${COMPONENT_DIR}/protocols/trezor/ethereum/definitions.c
            ${COMPONENT_DIR}/protocols/trezor/ethereum/normalizer.c
            ${COMPONENT_DIR}/protocols/trezor/failure.c
            ${COMPONENT_DIR}/protocols/trezor/features.c
            ${COMPONENT_DIR}/protocols/trezor/protobuf.c
            ${COMPONENT_DIR}/protocols/trezor/public_key.c
            ${COMPONENT_DIR}/protocols/trezor/session.c
            ${COMPONENT_DIR}/protocols/trezor/trace.c
            ${COMPONENT_DIR}/protocols/trezor/wire.c
            ${COMPONENT_DIR}/chains/tron/address.c
            ${COMPONENT_DIR}/chains/tron/authorize.c
            ${COMPONENT_DIR}/chains/tron/confirm.c
            ${COMPONENT_DIR}/chains/tron/path.c
            ${COMPONENT_DIR}/chains/tron/tx.c
            ${COMPONENT_DIR}/chains/tron/wallet.c
            -o ${eth_tron_address_gate_bin}
        COMMAND ${eth_tron_address_gate_bin}
        COMMAND ${CMAKE_COMMAND} -E touch ${eth_tron_address_gate_stamp}
        DEPENDS
            ${COMPONENT_DIR}/test/eth_tron_address_gate.c
            ${COMPONENT_DIR}/test/host_shims/esp_log.h
            ${COMPONENT_DIR}/chains/authorization.c
            ${COMPONENT_DIR}/chains/confirm_summary.c
            ${COMPONENT_DIR}/chains/confirm_summary.h
            ${COMPONENT_DIR}/chains/authorization.h
            ${COMPONENT_DIR}/chains/evm_abi.c
            ${COMPONENT_DIR}/chains/evm_abi.h
            ${COMPONENT_DIR}/crypto/keccak256.c
            ${COMPONENT_DIR}/crypto/keccak256.h
            ${COMPONENT_DIR}/chains/bitcoin/address.c
            ${COMPONENT_DIR}/chains/bitcoin/address.h
            ${COMPONENT_DIR}/chains/bitcoin/confirm.c
            ${COMPONENT_DIR}/chains/bitcoin/confirm.h
            ${COMPONENT_DIR}/chains/bitcoin/path.c
            ${COMPONENT_DIR}/chains/bitcoin/path.h
            ${COMPONENT_DIR}/chains/bitcoin/wallet.c
            ${COMPONENT_DIR}/chains/bitcoin/wallet.h
            ${COMPONENT_DIR}/chains/ethereum/address.c
            ${COMPONENT_DIR}/chains/ethereum/address.h
            ${COMPONENT_DIR}/chains/ethereum/authorize.c
            ${COMPONENT_DIR}/chains/ethereum/authorize.h
            ${COMPONENT_DIR}/chains/ethereum/confirm.c
            ${COMPONENT_DIR}/chains/ethereum/confirm.h
            ${COMPONENT_DIR}/chains/ethereum/digest.c
            ${COMPONENT_DIR}/chains/ethereum/digest.h
            ${COMPONENT_DIR}/chains/ethereum/path.c
            ${COMPONENT_DIR}/chains/ethereum/path.h
            ${COMPONENT_DIR}/chains/ethereum/sign.c
            ${COMPONENT_DIR}/chains/ethereum/sign.h
            ${COMPONENT_DIR}/chains/ethereum/tx.c
            ${COMPONENT_DIR}/chains/ethereum/tx.h
            ${COMPONENT_DIR}/chains/ethereum/tx_request.c
            ${COMPONENT_DIR}/chains/ethereum/tx_request.h
            ${COMPONENT_DIR}/chains/ethereum/wallet.c
            ${COMPONENT_DIR}/chains/ethereum/wallet.h
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/protocol.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/protocol.h
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/policy.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/policy.h
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/requests.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/requests.h
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/signing_state.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/signing_state.h
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/prev_tx_verifier.c
            ${COMPONENT_DIR}/protocols/trezor/bitcoin/prev_tx_verifier.h
            ${COMPONENT_DIR}/protocols/trezor/dispatcher.c
            ${COMPONENT_DIR}/protocols/trezor/dispatcher.h
            ${COMPONENT_DIR}/protocols/trezor/ethereum/protocol.c
            ${COMPONENT_DIR}/protocols/trezor/ethereum/protocol.h
            ${COMPONENT_DIR}/protocols/trezor/ethereum/definitions.c
            ${COMPONENT_DIR}/protocols/trezor/ethereum/definitions.h
            ${COMPONENT_DIR}/protocols/trezor/ethereum/normalizer.c
            ${COMPONENT_DIR}/protocols/trezor/ethereum/normalizer.h
            ${COMPONENT_DIR}/protocols/trezor/failure.c
            ${COMPONENT_DIR}/protocols/trezor/failure.h
            ${COMPONENT_DIR}/protocols/trezor/features.c
            ${COMPONENT_DIR}/protocols/trezor/features.h
            ${COMPONENT_DIR}/protocols/trezor/messages.h
            ${COMPONENT_DIR}/protocols/trezor/protobuf.c
            ${COMPONENT_DIR}/protocols/trezor/protobuf.h
            ${COMPONENT_DIR}/protocols/trezor/public_key.c
            ${COMPONENT_DIR}/protocols/trezor/public_key.h
            ${COMPONENT_DIR}/protocols/trezor/session.c
            ${COMPONENT_DIR}/protocols/trezor/session.h
            ${COMPONENT_DIR}/protocols/trezor/trace.c
            ${COMPONENT_DIR}/protocols/trezor/trace.h
            ${COMPONENT_DIR}/protocols/trezor/wire.c
            ${COMPONENT_DIR}/protocols/trezor/wire.h
            ${COMPONENT_DIR}/chains/tron/address.c
            ${COMPONENT_DIR}/chains/tron/address.h
            ${COMPONENT_DIR}/chains/tron/authorize.c
            ${COMPONENT_DIR}/chains/tron/authorize.h
            ${COMPONENT_DIR}/chains/tron/confirm.c
            ${COMPONENT_DIR}/chains/tron/confirm.h
            ${COMPONENT_DIR}/chains/tron/path.c
            ${COMPONENT_DIR}/chains/tron/path.h
            ${COMPONENT_DIR}/chains/tron/tx.c
            ${COMPONENT_DIR}/chains/tron/tx.h
            ${COMPONENT_DIR}/chains/tron/wallet.c
            ${COMPONENT_DIR}/chains/tron/wallet.h
            ${COMPONENT_DIR}/chains/path.h
        VERBATIM)
    add_custom_target(eth_tron_address_gate DEPENDS ${eth_tron_address_gate_stamp})
    add_dependencies(${COMPONENT_LIB} eth_tron_address_gate)
    add_custom_command(OUTPUT ${wallet_core_public_node_gate_stamp}
        COMMAND ${HOST_CC} -std=c11 -Wall -Wextra -Werror
            -I${COMPONENT_DIR}
            -I${COMPONENT_DIR}/test/host_shims
            -I${PROJECT_DIR}/components/libwally-core/upstream/include
            ${COMPONENT_DIR}/test/wallet_core_public_node_gate.c
            ${COMPONENT_DIR}/wallet_core/wallet_core.c
            -o ${wallet_core_public_node_gate_bin}
        COMMAND ${wallet_core_public_node_gate_bin}
        COMMAND ${CMAKE_COMMAND} -E touch ${wallet_core_public_node_gate_stamp}
        DEPENDS
            ${COMPONENT_DIR}/test/wallet_core_public_node_gate.c
            ${COMPONENT_DIR}/test/host_shims/esp_log.h
            ${COMPONENT_DIR}/wallet_core/wallet_core.c
            ${COMPONENT_DIR}/wallet_core/wallet_core.h
            ${COMPONENT_DIR}/jade_wally_verify.h
            ${COMPONENT_DIR}/keychain.h
            ${COMPONENT_DIR}/sensitive.h
            ${COMPONENT_DIR}/utils/util.h
            ${COMPONENT_DIR}/wallet.h
        VERBATIM)
    add_custom_target(wallet_core_public_node_gate DEPENDS ${wallet_core_public_node_gate_stamp})
    add_dependencies(${COMPONENT_LIB} wallet_core_public_node_gate)
else()
    message(FATAL_ERROR "No host C compiler found for ETH/TRON address gate tests")
endif()
