package jar;

public class PortReport {

    private String port;
    private String service;
    private String version;
    private String severity;
    private String risk;
    private String recommendation;

    public PortReport(String port, String service, String version,
                      String severity, String risk, String recommendation) {

        this.port = port;
        this.service = service;
        this.version = version;
        this.severity = severity;
        this.risk = risk;
        this.recommendation = recommendation;
    }

    public String getPort() { return port; }
    public String getService() { return service; }
    public String getVersion() { return version; }
    public String getSeverity() { return severity; }
    public String getRisk() { return risk; }
    public String getRecommendation() { return recommendation; }
}