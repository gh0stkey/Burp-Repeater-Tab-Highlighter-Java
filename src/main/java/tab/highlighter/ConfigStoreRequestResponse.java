package tab.tabhighlighter;

import tab.Utilities;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class ConfigStoreRequestResponse implements IHttpRequestResponse {

    private final IHttpService service;
    private byte[] requestBytes;
    private String value;

    public ConfigStoreRequestResponse(URL url, String value) {
        long timestamp = System.currentTimeMillis() / 1000L;
        int port = url.getPort() > 0 ? url.getPort() : url.getProtocol().equalsIgnoreCase("https") ? 443 : 80;
        this.service = Utilities.helpers.buildHttpService(url.getHost(), port, false);
        this.requestBytes = Utilities.helpers.buildHttpRequest(url);
        this.value = value;
        // add to scope so that it will always be saved with the project
        Utilities.callbacks.includeInScope(url);
    }

    @Override
    public byte[] getRequest() {
        return requestBytes;
    }

    @Override
    public void setRequest(byte[] message) {
    }

    @Override
    public byte[] getResponse() {
        long timestamp = System.currentTimeMillis() / 1000L;

//        String randomString = new Random().ints(48, 123)
//                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
//                .limit(50)
//                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
//                .toString();
//
        String response = String.format(
                "HTTP/1.1 200 OK\r\nX-TimeStamp: %s\r\nContent-Type: text/plain\r\n\r\n%s",
                timestamp,
//                randomString,
                value
        );
        return response.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void setResponse(byte[] message) {
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
    }

    public void saveToProject() {
        try {
            Utilities.callbacks.addToSiteMap(this);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
