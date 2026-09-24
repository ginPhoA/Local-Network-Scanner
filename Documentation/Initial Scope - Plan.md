# Local Network Scanner
**IMPORTANT**
This application will ==NOT== be user-controlled, meaning they cannot modify, influence, or parse information that may pose a security risk to themselves and others.

Some attacks may include:
- Cross-Site Scripting (XSS)
- SQL-injection (SQLi)
- Command (CLI) injection (Shell commands)
- File/Directory traversal (Abusing exposed file path within the URL ../../../)

### Initial Idea
This is a self-hosted, containerised (Docker) web-application which runs authorised nmap scans on open-ports against a chosen device (HomeLab, Desktop PC).
- Use the users **PUBLIC** IP address (crucial)

The stage 0 MVP is a working webpage with a singular button that starts an nmap scan with the users approval. The scan checks which network ports are open and identifies services running on them.
- nmap will produce a .XML results file, which the application parses and saves into a local PostgreSQL database
- The results can be pulled and displayed on the webpage

### Future Iterations
Future versions may have the following features:
- Users can compare new scans with previous results. Aid in identifying changes/inconsistencies within the data
	- Newly open ports
	- New services open'd

- AI-assisted tool which aids in:
	- Reports .XML data in non-technical, understandable language
	- Display common attacks on each port, and how to protect them from breaches

### All Features Planned - Currently
**Stage 0 - 1**
- Users approve and start an nmap scan through a web interface.
    
- nmap scans the target (Machine) for open ports and detected services.
    
- Scan results are saved as .XML and parsed into a local PostgreSQL database.
    
- Users can view saved scan results through the web application (Widget)

**Stage 2 >**
- Future versions can compare scans to identify differences over time.
    
- Future versions may use AI to create easier-to-read security reports.
    
- The project will use GitHub Actions for CI/CD and automated security testing.

### User Onboarding
**TD!**

