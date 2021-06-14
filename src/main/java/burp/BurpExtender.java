package burp;

import tab.highlighter.Highlighter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        new Highlighter(callbacks);

    }

}
