# Model and implementation of user activity tracking utilizing the TLS Client Hello’s `server_name` extension - Supporting Documents

This repository serves as a store for source code and other related documents regarding the paper on user activity tracking utilizing the TLS Client Hello’s `server_name` extension.

## Abstract
This paper puts forward a feasible,  non-intrusive,  method of tracking  user  activity  using  TLS’s  Client  Hello  section  of  a handshake  (specified  in  the  TLS  protocol), namely  the `server_name` extension. This method can provide an attacker with relevant information regarding patterns and services utilized inside of the target network,  further  expanding  their  understanding  of  the  attack surface, potentially, serving as a tool to determine the timing of an attack or, even, provide an attacker with knowledge of a point of entry to a given system. It is noteworthy that TLS Client Hellos will be encrypted in a future version of the TLS protocol, rendering this method infeasible in fully updated networks.

## Contents

* [`paper.pdf`](/paper.pdf) - The paper in pdf format
* [`implementation/client`](/implementation/client) - Holds the code for the daemon implementation 
* [`implementation/client`](/implementation/client) - Holds the code for the client implementation 
* [`data/domains.txt`](/data/domains.txt) - Domain list used to get the figures in the filtering section of the paper, source (adapted): [here](https://github.com/vysecurity/DomainFrontingLists/blob/master/CloudFront-total.txt)


## License 

![License Badge](https://mirrors.creativecommons.org/presskit/buttons/80x15/svg/by-nc.svg)

The aforementioned code and documents are protected and released to the public under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) License which can be viewed in license.md or on the Creative Commons website (https://creativecommons.org/licenses/by-nc/4.0/). Any failure to comply with the terms designated in the license will be met with swift judicial action by the author.

By downloading, executing or otherwise transferring the contents of this repository by any means you are legally bound to the terms stipulated in the license.