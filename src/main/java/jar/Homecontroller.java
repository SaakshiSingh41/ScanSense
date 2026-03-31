package jar;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

@Controller
public class Homecontroller {

    List<PortReport> lastReports = new ArrayList<>();
    List<String> lastDirectories = new ArrayList<>();


    @GetMapping("/")
    public String home() {
        return "index";
    }

    @PostMapping("/scan")
    public String scan(@RequestParam String target, Model model) {

        List<PortReport> reports = new ArrayList<>();
        List<String> directories = new ArrayList<>();

        try {

            ProcessBuilder pb = new ProcessBuilder(
                    "nmap","-sV","-oX","scan.xml",target
            );

            Process process = pb.start();
            process.waitFor();


            File xmlFile = new File("scan.xml");

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(xmlFile);

            NodeList ports = doc.getElementsByTagName("port");

            for(int i=0;i<ports.getLength();i++){

                Element portElement = (Element) ports.item(i);

                String port = portElement.getAttribute("portid");

                Element service = (Element) portElement.getElementsByTagName("service").item(0);

                String serviceName = service.getAttribute("name");
                String version = service.getAttribute("product") + " " + service.getAttribute("version");

                String severity = getSeverity(serviceName);
                String risk = getRisk(serviceName);
                String recommendation = getRecommendation(serviceName);

                reports.add(new PortReport(
                        port,
                        serviceName,
                        version,
                        severity,
                        risk,
                        recommendation
                ));
            }


            ProcessBuilder gobuster = new ProcessBuilder(
                    "gobuster","dir",
                    "-u","http://"+target,
                    "-w","/usr/share/wordlists/dirb/common.txt"
            );

            Process gobusterProcess = gobuster.start();

            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(gobusterProcess.getInputStream()));

            String line;

            while((line = reader.readLine()) != null){

                if(line.startsWith("/")){
                    directories.add(line);
                }

            }

            gobusterProcess.waitFor();


        } catch(Exception e){
            e.printStackTrace();
        }

        lastReports = reports;
        lastDirectories = directories;

        model.addAttribute("target",target);
        model.addAttribute("reports",reports);
        model.addAttribute("directories",directories);

        return "result";
    }



    @GetMapping("/download")
    @ResponseBody
    public String downloadReport() throws Exception {

        FileWriter writer = new FileWriter("ScanSense_Report.txt");

        writer.write("ScanSense Detailed Security Report\n\n");

        writer.write("Open Ports Analysis\n\n");

        for(PortReport r : lastReports){

            writer.write("Port: " + r.getPort() + "\n");
            writer.write("Service: " + r.getService() + "\n");
            writer.write("Version: " + r.getVersion() + "\n");
            writer.write("Severity: " + r.getSeverity() + "\n");

            writer.write("Risk:\n" + r.getRisk() + "\n");

            writer.write("Mitigation:\n" + r.getRecommendation() + "\n");

            writer.write("\n-----------------------------\n\n");

        }


        writer.write("\nDirectory Enumeration Results\n\n");

        writer.write("Directory scanning was performed using Gobuster.\n");
        writer.write("Directory enumeration attempts to discover hidden\n");
        writer.write("web resources that are not directly linked.\n\n");

        for(String d : lastDirectories){
            writer.write(d + "\n");
        }

        writer.close();

        return "Detailed report saved as ScanSense_Report.txt in project folder.";
    }




    private String getSeverity(String service){

        service = service.toLowerCase();

        if(service.contains("ssh")) return "MEDIUM";
        if(service.contains("http")) return "MEDIUM";
        if(service.contains("ftp")) return "HIGH";

        return "LOW";
    }



    private String getRisk(String service){

        service = service.toLowerCase();

        if(service.contains("ssh"))
            return "SSH service exposed. Attackers may attempt brute-force login attempts.";

        if(service.contains("http"))
            return "Web server exposed. Vulnerable web applications may allow data leaks or remote code execution.";

        return "Unknown service exposed which increases attack surface.";
    }



    private String getRecommendation(String service){

        service = service.toLowerCase();

        if(service.contains("ssh"))
            return "Disable password login. Use SSH key authentication and restrict access using firewall rules.";

        if(service.contains("http"))
            return "Update the web server software. Disable directory listing and implement a Web Application Firewall.";

        return "Close unused ports using firewall rules such as ufw or iptables.";
    }

}