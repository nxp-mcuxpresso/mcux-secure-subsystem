# Revision History

# **KW45_A1_A2_SDK_FW_1_1_0_0**

## Release description

This is the release note for loadable EdgeLock Enclave (ELE) Firmware. This ELE FW is authenticated and installed by ELE ROM. It provides new features, fixes, and exposes cryptographic services.

## FW updates: 
* Update of HMAC one go service to support message bigger than 64kB
API remain same as in ROM service, only maximal supported message length updated from 65536 bytes to 4294967295 bytes for HMAC algorithm. 

* DRBG initialized according NIST SP 800-90b (1024bit validated against 512bit validated in ROM)
API remain same as in ROM service, if the high quality random number is requested for the first time, the DRBG is initialized by entropy from TRNG with validated 1024bits by statistical checks, ROM implementation validates only 512bits. This is done to be compliant with NIST SP 800-90b. DRBG is instantiated only once till S200 reset. If was previously used ROM service to initialize DRBG, the firmware load removes the global flag and once is high quality random number again requested, DRBG will be initialized newly in a way compliant with NIST SP 800-90b. 

## Supported revsion
* KW45

## Backward compatibility
Software that runs on KW45 ELE ROM should run also on KW45 ELE ROM with loaded FW with documented exceptions. 

## Build instructions
The FW cannot be rebuilt and is available in binary form only.