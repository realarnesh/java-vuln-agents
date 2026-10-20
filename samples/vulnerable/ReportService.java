package com.example.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ReportService {
    private static final String BASE_DIR = "/var/reports/";

    public InputStream openReport(String fileName) throws IOException {
        File file = new File(BASE_DIR + fileName); // expect: PATH
        return new FileInputStream(file);
    }

    public Process exportPdf(String reportName) throws IOException {
        return Runtime.getRuntime().exec("wkhtmltopdf " + reportName + " out.pdf"); // expect: CMDI
    }

    public Process listReports() throws IOException {
        // Fixed command with no user input is fine.
        return Runtime.getRuntime().exec("ls /var/reports");
    }
}
