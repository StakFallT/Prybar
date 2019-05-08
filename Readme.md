                                                                               

                                                         ╓▄█████▄ç              
                                                        ▄██████████▓▄╓          
                                                      ▄▓▓▓▓█████████▓█          
                                                    ▄▓▓▓▓▓▌└    ╙▀▓███p         
                                                 ,▄██▓▓▓▓▀         `╙▀M         
                                               ╓▓██▀█▓▓▀`                       
                                            .▄█████▓▓▀                          
                                          ╓▄███████▀                            
                                        ▄████████╨                              
                                     ,▄███████▀└                                
                                   ▄▓███████▀                                   
                                ,▄███████▓Γ                                     
                              ▄████████▀└                                       
                           ╓▄████████▀                                          
                        ╓▄████████▀┘                                            
                     ╓▄████▀▄███▀                                               
                 ,▄▓█████████▀└                                                 
             ,▄▄██████████▀╙                                                    
         ▄▄████████████▀╙                                                       
         ▀██████████▀└                                                          
          ▐████▀▀╙                                                              
           ╙└                                                        


	Prybar


	Utilizies a shim dll in combination with rundll32 (system32 or syswow64) to bytes into a variable in
	the shim dll, and performs a runtime loading of those bytes into the DLLs memory space and begins execution of those bytes.
	Can be useful if CreateProcess api is blocked.
	PE32 image loading still needs to be implemented before applications can be loaded. PE32 image loading for execution will require rebasing the image address to fit the shim dll's address, iterating
	the imported DLLs, loading those into a variable, and then patching the import address table to reflect the new addresses.

	There are two versions, a 32-bit and a 64-bit. Currently, the 64-bit version is somewhat behind in development of the 32-bit
	version. However, porting the 32-bit version to 64-bits should be fairly straightforward.

	-- Brandon Morris
