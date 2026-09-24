Develop, run, and inspect an authorised nmap scan via python script and save its .xml results in a folder within the repository.

### Prerequisites
- locally install nmap and python on your machine (PC, Desktop OS)
- A machine authorised to be scanned

### Implementation
- Simple python scanner targeting a fixed target (local machine) within trusted parameters
- Small nmap command line that emits an .XML file, stored locally in the repository
- nmap scans use the **PUBLIC** 'IP address', not **PRIVATE**
- Results are timestamped
	- When the scan was initiated
	- If test failed, clearly show why it failed (research)
	- If test succeeded, display results and store

### Exclusions
This stage is limited to **JUST** having a simple webpage with a widget responsible for the nmap scan. Nothing else.

### Security (Longterm Value)
- **Server-side Resolution**: Grabs the users public IP address from the backend via trusted API. Prevents user-side IP spoofing and network enumeration (SSRF) attacks.
- **Kernel-Level Execute Routing**: Code invokes `subprocess.run` with `shell=false` to pass arguments in a strict vector array, bypassing the OS shell to prevent CLI injections.
- **RegEx Sanitation**: Validates target string against an IPv4 regular expression (Single Line) before executing the scan. Defend against data poisoning.
- **Zero-Trust Inputting**: Removes client-side injection by accepting zero browser parameters, URL, &  SQL queries.
- **Deterministic Repository Scoping**: Resolves storage destination relative to the absolute local directory path, which contains .XML outputs. Removing traversal risks
- **Operationally-Bound Execution**: Enforces a 120-second timeout on binary runtime alongside the TCP handshake.
	- Will help heavily in preventing unauthorised tool abuse/actions by AI and LLM.
	- AI will likely be implemented in the final stages of the project to aid in displaying .XML results in readable, non-technical language.

### Definition-of-Done
- [ ] The approved target scans successfully.
- [ ] XML is saved and can be inspected.
- [ ] No way that allows users to interact with the underlying infrastructure (code)
	- [ ] Browser Input
	- [ ] CLI Input
	- [ ] Shell strings


**Next**: Turn the .XML into a structured, queryable scan history in a PostgreSQL database.
[[Stage1- .XML in a Database]]