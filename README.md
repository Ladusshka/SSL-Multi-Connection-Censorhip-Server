# SSL-Multi-Connection-Censorhip-Server


Text Censorship Server (Multi-Client + SSL)


Features

 Multi-Client Support
        The server can handle multiple clients simultaneously (concurrency model is your choice: e.g., threads or processes).
        Each client has its own list of forbidden words. For example, if one client forbids "dog", it does not affect another client that did not forbid "dog".

 
 
 
 SSL/TLS Encryption
        All connections are secured via SSL/TLS.
        Certificates are imported from provided files (see below).
        The client expects the SSL hostname of the server to be "bi.sip".
        Proper error handling for SSL handshake failures or protocol attacks is strongly encouraged.



Protocol
        Two-Phase Protocol:
            Forbidden Words Phase: The client sends its forbidden words, separated by 0x1E, ending with 0x1F.
            Censorship Phase: The client sends text blocks (up to 1000 characters) separated by 0x1E, ending with 0x1F.
        The server censors occurrences of each forbidden word (exact case-sensitive match) by replacing every character of the word with '-'.
        For more protocol details, see the previous project’s README.






Timeout & Socket Details
        The server should still have a 3-second timeout for inactivity per client.
        Must handle partial reads/writes (packet fragmentation and merging).
