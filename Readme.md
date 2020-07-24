                                                                               

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

Update 07/24/2020:
	The project last left off beginning to parse the PE header of an executable specified (I actually don't recall if that work had been comitted since then or not -- I'd have to check the logs and date/timestamps). In either case, when debugging, an error of "Out of memory" is shown despite their being plenty of memory. Further testing needs to be performed to determine if it is the workstation the code is being developed on, or if there is an issue with the usage of the various API calls been used. Other projects being worked on are using some of the libraries that started out of my work on this project. As a result, this project will benefit as it will be eventually rolled into it providing a more thorough library. This project is NOT dead, just I have a ton of projects I'm working on and when I can, I'll cycle back around to this one.
