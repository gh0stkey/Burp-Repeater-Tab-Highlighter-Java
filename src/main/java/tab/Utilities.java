package tab;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

import javax.swing.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;

public class Utilities {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    public Utilities(final IBurpExtenderCallbacks _callbacks) {
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }


    public static void println(String _message) {
        stdout.println(_message);
    }
    public static void err(String _message) {
        stderr.println(_message);
    }
    public static void err(String _message, Exception _e) {
        stderr.println(_message);
        _e.printStackTrace(stderr);
    }



}
