<h1>Reverse-Engineering</h1>

A project done when going through "Concept And Techniques For Malware Analysis" module during my university
 
<h2>Description</h2>

Performing Reverse Engineering on a Malware(.exe) 

<h2>Environment and Tools Used</h2>

- Conduct the reverse engineering on <b>Flare</b> a windows 10 virtual environment
- <b>IDA Pro</b> 
- <b>Resource Hacker</b> 

<h2>Analysis</h2>
<p align="left">
<b>Qns: Provide both the raw file offset of the EXE that contains the two config.</b>
<br />
<img src="https://imgur.com/TEKi2ug.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Ans: 1B610 and 1B640
<br />
<br />
<b>Qns: Provide both the value of the config string in raw hex bytes.</b>
<br />
<img src="https://imgur.com/9AV25gh.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<img src="https://imgur.com/F5AlYXG.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
<br />
<b>Qns: Are you able to find these config string within IDA (Use hex view and search->Text). If not, please provide a brief explanation. (Hint - What does opening the PE file in IDAPro simulates in the PE file execution process)</b>
<br />
<img src="https://imgur.com/nlLkWwu.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
No, the main functions of IDA Pro are debugger and disassembler. IDA Pro's opening of a PE file essentially emulates the disassembly of the binary code, code structure analysis, and the logic flow of the program. 
<br />
<br />
<b>Qns: Please provide a brief description (referencing addresses from IDA) including screenshots of the encoding algorithm used. Including the keys/value used for the encoding in hex.</b>
<br />
<img src="https://imgur.com/qfvwg0K.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
The return value of the config string is the parameter for the function at 00402877.
<br />
<br />
<img src="https://imgur.com/Iz3gEhm.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
The function encodes the string by adding ‘z’ to each char (located at 00401AB9) and then XOR with 0x19 (located at 00401AC6).
<br />
<br />
<b>Qns: There are 2 algorithm to generate Service names for persistence. Please provide a brief description (referencing addresses from IDA) including screenshots. </b>
<br />
<img src="https://imgur.com/cHh1DZM.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
IpServiceName parameter of API CreateServiceA is the return value of function sub_401FE0. Hence, highly likely the function contains the algorithm to generate the service name.
<br />
<br />
<img src="https://imgur.com/1fx5tko.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Firstly, it checks for registry date whether netsvcs exist using the handle HKEY_LOCAL_MACHINE under SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost which may be the potential target for the persistence to hide in blindsight.
<br />
<br />
<img src="https://imgur.com/L0N0VWU.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
The formatted string output is netsvcs_0x%d. It checks if there is an existing service name with the result of the query before, if not it will modify the variable that the format token will take in.
<br />
<br />
<img src="https://imgur.com/bHfvSK4.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
If no existing strings created before, it will overwrite with new netsvcs_0x%d. It may be for indexing purpose.
<br />
<br />
<img src="https://imgur.com/bHfvSK4.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Within the same subfunction, first, it opens HKLM_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NTCurrentVersion\Svchost key and uses the key handle query on netsvcs service. 
The parameter lpData variable that stored the query data is located at ebp+Data (004021BE)
<br />
<br />
<img src="https://imgur.com/fyAi9mA.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
GetSystemDirectoryA function data is in ebp+Buffer (00402236). Using the query data stored (004021BE) in Figure 10 as a condition and variable to loop and generate the service name by checking for null char (00402254) within the query data. It opens a key using HKEY_LOCAL_MACHINE and the subkey is the formatted output from wsprintfA (SYSTEM\CurrentControlSet\Services\%s), located at ebp+Subkey (0040225E). 
<br />
<br />
<img src="https://imgur.com/Vgk6IhR.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
If open fails, it closes the key, increments the condition variable, and repeats again. If opened successfully, it gets the file attribute of the dll under the system directory. If the file does not exist, it creates a service with the name as the query data in Figure 10 under path %SystemRoot%\System32\svchost.exe -k netsvcs to be able to access it.
<br />
<br />
<b>Qns: Is it possible to statically extract the dropped DLL from the first sample server.exe. Please provide a brief description including screenshots.</b>
<br />
<img src="https://imgur.com/8GixLIF.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
By looking at resource editor tab, we can see that there is another exe embedded in the server.exe file
<br />
<br />
<img src="https://imgur.com/VY7JU2e.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<img src="https://imgur.com/6PMmc7F.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Using a resource hacker to extract the file and import it back to IDA to further RE.
<br />
<br />
<b>Qns: What is the service DLL location that is stated after the service is created, provide a screenshot of this information. Are you able to find the DLL at this location, if not please provide an adequate explanation</b>
<br />
<img src="https://imgur.com/YWbDng3.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<img src="https://imgur.com/6LbimpP.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Path= %SystemRoot%\System32\svchost.exe -k netsvcs
<br />
<br />
<img src="https://imgur.com/aQ0W0Nl.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
No, it may be because the mutex created does not exist which result in the code returning instead of flowing to the other branch that creates the service
<br />
<br />
<b>Qns: Previously, the config string was found in part 1. Please elaborate on how this DLL obtains it config string again.</b>
<br />
<img src="https://imgur.com/wA3StXy.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<img src="https://imgur.com/S52TMzQ.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Using the same technique from server.exe, the dll search for the file with AAAAAA ASCII values which is part of the config string stated in part one. Then it creates and reads the file.
<br />
<br />
<b>The malware enumerates host system information before sending the information to the C2 server at function sub_10009700. Please state the 2 of multiple data enumerated from the host.</b>
<img src="https://imgur.com/ED1pf1j.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<img src="https://imgur.com/HRlRjvl.png" height="80%" width="80%" alt="IMAGE NOT AVAILABLE"/>
<br />
Socket number and time since the system was started.
</p>

