cmake_minimum_required(VERSION 3.3)
project(ubicd)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(APPLE)
    include_directories(/usr/local/openssl-1.1/include/)
    include_directories(/usr/local/opt/openssl@1.1/include/openssl/)
    include_directories(/usr/local/opt/openssl@1.1/include/)
    include_directories(/usr/local/openssl-1.1/include/openssl/)
    include_directories(/usr/local/include/)
    include_directories(/usr/local/include/leveldb/)
    #link_directories(/usr/local/src/openssl-1.1.0f/)
    link_directories(/usr/local/opt/openssl@1.1/lib)
    link_libraries(crypto.1.1)

    link_directories(/usr/local/opt/pcsc-lite/lib/)
    include_directories(/usr/local/opt/pcsc-lite/include/PCSC/)
    link_libraries(pcsclite)

elseif(UNIX)
    include_directories(/usr/include/openssl/)
    link_libraries(pcsclite)
    include_directories(/usr/include/PCSC)
    link_libraries(crypto)
endif()
include_directories(/usr/include/leveldb)

find_package(OpenSSL 1.1)
if(NOT OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(FATAL_ERROR "Could not find OpenSSL v1.1")
endif()

add_definitions(${Boost_LIB_DIAGNOSTIC_DEFINITIONS})
find_package(Boost REQUIRED)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Could not find boost")
endif()
include_directories(${Boost_INCLUDE_DIRS})
include_directories(/usr/include/openssl/)
link_libraries(boost_serialization)
link_libraries(boost_system)
link_libraries(boost_filesystem)
link_libraries(leveldb)
link_libraries(pthread)
link_libraries(ssl)

set(SOURCE_FILES

        Crypto/CreateSignature.cpp
        Crypto/CreateSignature.h
        Crypto/Sha256.cpp
        Crypto/Sha256.h
        Crypto/VerifySignature.cpp
        Crypto/VerifySignature.h

        Tools/Hexdump.cpp
        Tools/Hexdump.h
        Tools/Log.h
	Tools/Helper.h

        NtpEsk/NtpEsk.cpp
        NtpEsk/NtpEsk.h
        NtpEsk/NtpEskSignatureRequestObject.h
        NtpEsk/NtpEskSignatureVerificationObject.h

        NtpRsk/NtpRsk.cpp
        NtpRsk/NtpRsk.h
        NtpRsk/NtpRskSignatureRequestObject.h
        NtpRsk/NtpRskSignatureVerificationObject.h

        Crypto/Ripemd160.cpp
        Crypto/Ripemd160.h
        Crypto/Hash160.cpp
        Crypto/Hash160.h
        Crypto/Hash256.cpp
        Crypto/Hash256.h
        Crypto/PassportCrypto.cpp
        Crypto/PassportCrypto.h
	Crypto/X509Helper.cpp
	Crypto/X509Helper.h
	
        CertStore/Cert.cpp
        CertStore/Cert.h
        CertStore/CertStore.cpp
        CertStore/CertStore.h
	CertStore/CertHelper.cpp
        CertStore/CertHelper.h
	
        support/allocators/zeroafterfree.h
        support/cleanse.h
        support/clease.cpp

        PathSum/PathSum.cpp
        PathSum/PathSum.h

        PassportReader/LDS/LDSParser.cpp
        PassportReader/LDS/LDSParser.h
	PassportReader/LDS/Iso19794Parser.cpp
        PassportReader/LDS/Iso19794Parser.h
        PassportReader/PKCS7/PKCS7Parser.cpp
        PassportReader/PKCS7/PKCS7Parser.h
        PassportReader/Reader/BacKeys.cpp
        PassportReader/Reader/BacKeys.h
        PassportReader/Reader/Reader.cpp
        PassportReader/Reader/Reader.h
        PassportReader/Reader/SessionKeys.cpp
        PassportReader/Reader/SessionKeys.h
        PassportReader/Reader/NFC.cpp
        PassportReader/Reader/NFC.h

        Transaction/Transaction.cpp
        Transaction/Transaction.h Block.cpp
        Transaction/TxIn.cpp
        Transaction/TxIn.h
        Transaction/TxOut.cpp
        Transaction/TxOut.h

        Base58.h
        Base58.cpp
        serialize.h
        prevector.h
        streams.h
        AddressStore.cpp
        AddressStore.h
        main.cpp
        Block.h
        Chain.cpp
        Chain.h
        BlockHeader.cpp
        BlockHeader.h
        Address.cpp
        Address.h
        UAmount.h
        ChainParams.h
        MerkleTree.cpp
        MerkleTree.h
        Wallet.cpp
        Wallet.h

        Crypto/ECCtools.cpp
        Crypto/ECCtools.h
        FS/FS.cpp
        FS/FS.h
        Test/Test.cpp
        Test/Test.h
        BlockStore.cpp
        BlockStore.h
        BlockCreator/Mint.cpp
        BlockCreator/Mint.h
        UBICalculator.cpp
        UBICalculator.h
        Loader.cpp
        Loader.h
        TxPool.cpp
        TxPool.h

        Network/Network.cpp
        Network/Network.h
        Network/NetworkCommands.h
        Network/Peers.h
        Network/NetworkMessage.h
        Network/NetworkMessageHandler.cpp
        Network/NetworkMessageHandler.h
        Network/BanList.h
        Network/BlockCache.h

        DSCAttachedPassportCounter.cpp
        DSCAttachedPassportCounter.h
        DB/DB.cpp
        DB/DB.h

        AddressHelper.h
        JSON/Api.cpp
        JSON/Api.h
        REST/ApiServer.cpp
        REST/ApiServer.h
        Network/Server.h

        Network/Peers.cpp
        Consensus/Vote.h
        Consensus/VoteStore.h
        Consensus/Delegate.cpp
        Consensus/Delegate.h
        App.h
        Transaction/TransactionHelper.cpp
        Transaction/TransactionHelper.h
        Time.h
        WebInterface/WebInterface.cpp
        WebInterface/WebInterface.h
        Config.cpp
        Config.h
        Tools/Log.cpp

        endian.h
        Base64.cpp
	Base64.h
	
	Fixes.cpp
        Fixes.h
	
	Scripts/UScript.h
        Scripts/AddCertificateScript.h
        Scripts/NtpskAlreadyUsedScript.h
        Scripts/KycRequestScript.h
        Scripts/PkhInScript.h
        Scripts/DeactivateCertificateScript.h

        KYC/MRZResponseObject.h
        KYC/MRZParser.cpp
        KYC/MRZParser.h)
add_executable(ubicd ${SOURCE_FILES})

set(SOURCE_FILES_CLI
        cli/main.cpp
        cli/HttpClient.cpp
        cli/HttpClient.h
        cli/ApiKey.cpp
        cli/ApiKey.h
        cli/FS/FS.h
	    cli/FS/FS.cpp
        )

if(UNIX AND NOT APPLE)
	set(SOURCE_FILES_CLI
		cli/main.cpp
		cli/HttpClient.cpp
		cli/HttpClient.h
		cli/ApiKey.cpp
		cli/ApiKey.h
		cli/FS/FS.h
		cli/FS/FS.cpp
		)

	add_executable(ubic ${SOURCE_FILES_CLI})

	install(CODE "execute_process(COMMAND Static/install.sh)")
endif()
