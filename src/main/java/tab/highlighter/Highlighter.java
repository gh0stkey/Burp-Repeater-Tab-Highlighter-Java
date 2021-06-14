package tab.highlighter;

import tab.Utilities;
import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.util.List;
import java.util.*;

public class Highlighter implements IContextMenuFactory, IExtensionStateListener {

    public static final String NAME = "Repeater Tab Highlighter";

    TabIndexPCL tabListener;

    private JTabbedPane repeater = null;


    public Highlighter(IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        Utilities.callbacks.setExtensionName(NAME);

        for (Frame frame : Frame.getFrames()) {
            find_repeater(frame);
        }
        if (repeater == null) {
            Utilities.err("ERROR: Unable to locate Repeater");
            return;
        }

        Utilities.callbacks.registerExtensionStateListener(this);
        Utilities.callbacks.registerContextMenuFactory(this);

        repeater.addPropertyChangeListener("indexForTabComponent", tabListener = new TabIndexPCL());

        Utilities.println("Tab Highlighter");
    }

    class TabIndexPCL implements PropertyChangeListener {

        private boolean alive = true;

        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            if (!alive) {
                return;
            }
            if ((int)evt.getNewValue() >= 0) {
                delayedSave(2000);
            }
        }

        // sometimes listeners don't get removed when unloading the extension. This will at least kill it off.
        public void kill(Component owner) {
            this.alive = false;
            owner.removePropertyChangeListener(this);
        }

    }

    private void find_repeater(Container container) {
        if (container.getComponents() != null && this.repeater == null) {
            try {
                if (container instanceof JRootPane) {
                    JMenuBar menubar = ((JRootPane) container).getJMenuBar();
                    if (menubar != null && menubar.getMenu(0).getText().equalsIgnoreCase("Repeater")) {
                        if (((JRootPane) container).getContentPane().getComponent(0) instanceof JTabbedPane) {
                            this.repeater = (JTabbedPane) ((JRootPane) container).getContentPane().getComponent(0);
                            return;
                        }
                    }
                }

                for (Component c : container.getComponents()) {
                    if (c instanceof JTabbedPane) {
                        JTabbedPane t = (JTabbedPane)c;
                        for (int x = 0; x < t.getTabCount(); x++) {
                            if (t.getTitleAt(x).equalsIgnoreCase("Repeater")) {
                                this.repeater = (JTabbedPane) t.getComponentAt(x);
                                return;
                            }
                        }
                    }
                    if (c instanceof Container) {
                        find_repeater((Container) c);
                    }
                }
            } catch (Exception e) {
            }
        }
    }

    private boolean hasDelayedSave = false;
    private void delayedSave(int delay) {
        if (hasDelayedSave) {
            return;
        }
        hasDelayedSave = true;
        new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        hasDelayedSave = false;
                    }
                },
                delay
        );
    }


    private void highlightTab(Highlight highlight) {
        highlightTab(highlight, -1);
    }

    private void highlightTab(Highlight highlight, int idx) {
        try {
            if (idx < 0) {
                idx = repeater.getSelectedIndex();
            }
            boolean changed = false;
            boolean hasListener = false;

            Container tab = (Container) repeater.getTabComponentAt(idx);
            JTextField tabLabel = (JTextField) tab.getComponent(0);

            if (!tabLabel.getForeground().equals(highlight.getColor())) {
                changed = true;
                // "disable" the listener before making this change
                for (PropertyChangeListener l : tabLabel.getPropertyChangeListeners("disabledTextColor")) {
                    if (l instanceof TabStylePCL) {
                        ((TabStylePCL) l).setHighlight(highlight);
                        hasListener = true;
                        break;
                    }
                }
                repeater.setBackgroundAt(idx, highlight.getColor());
            }

            Font newFont = tabLabel.getFont().deriveFont(highlight.getStyle());
            if (!tabLabel.getFont().equals(newFont)) {
                changed = true;
                tabLabel.setFont(newFont);
            }

            if (changed) {
                // create a listener if we don't have one already.
                if (!hasListener) {
                    tabLabel.addPropertyChangeListener("disabledTextColor", new TabStylePCL(tabLabel, highlight));
                }

            }
        } catch (Exception e) {
            Utilities.err("highlightTab error", e);
        }
    }

    class TabStylePCL implements PropertyChangeListener {

        private boolean alive = true;
        private JTextField label;
        private Highlight highlight;
        private boolean deliberateChange = false;

        public TabStylePCL(JTextField label, Highlight highlight) {
            this.label = label;
            this.highlight = highlight;
        }

        public void setHighlight(Highlight highlight) {
            this.highlight = highlight;
            this.deliberateChange = true;
        }

        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            // make sure the listener is inactive if it wasn't removed cleanly
            if (!alive) {
                return;
            }

            if (deliberateChange) {
                deliberateChange = false;
                return;
            }

            // dirty hack with a delay to revert the colours, because this event sometimes fires too soon :|
            new java.util.Timer().schedule(
                    new TimerTask() {
                        @Override
                        public void run() {
                            deliberateChange = true;
                            label.setForeground(highlight.getColor());
                            label.setDisabledTextColor(highlight.getColor());
                            delayedSave(2000);
                        }
                    },
                    100
            );
        }

        public void kill(Component owner) {
            alive = false;
            owner.removePropertyChangeListener(this);
        }

    }

    @Override
    public void extensionUnloaded() {
        // remove all listeners
        if (tabListener != null) {
            tabListener.kill(repeater);
        }
        for (int idx=0; idx<repeater.getTabCount()-1; idx++) {
            Component tabLabel = ((Container) repeater.getTabComponentAt(idx)).getComponent(0);
            for (PropertyChangeListener pcl : tabLabel.getPropertyChangeListeners()) {
                if (pcl instanceof TabStylePCL) {
                    ((TabStylePCL)pcl).kill(tabLabel);

                }
            }
        }
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation.getToolFlag() != Utilities.callbacks.TOOL_REPEATER) {
            return null;
        }

        JMenu subMenu = new JMenu("Highlight Tab");
        subMenu.add(createMenuItem("Red", new Color(255, 50, 0)));
        subMenu.add(createMenuItem("Orange", new Color(255, 165, 0)));
        subMenu.add(createMenuItem("Yellow", new Color(255, 255, 0)));
        subMenu.add(createMenuItem("Green", new Color(0, 204, 51)));
        subMenu.add(createMenuItem("Cyan", new Color(0, 255, 255)));
        subMenu.add(createMenuItem("Blue", new Color(102, 153, 255)));
        subMenu.add(createMenuItem("Pink", new Color(255, 192, 203)));
        subMenu.add(createMenuItem("Purple", new Color(255, 0, 255)));
        subMenu.add(createMenuItem("Purple", new Color(128, 128, 128)));
        subMenu.add(createMenuItem("None", null));

        List<JMenuItem> menu = new ArrayList<>();
        menu.add(subMenu);
        return menu;
    }

    private JMenuItem createMenuItem(String name, Color colour) {
        if (colour != null) {
            JMenu subSubMenu = new JMenu(name);
            subSubMenu.setForeground(colour);
            subSubMenu.add(createMenuItemStyled("Normal", colour, Font.PLAIN));
            subSubMenu.add(createMenuItemStyled("Bold", colour, Font.BOLD));
            subSubMenu.add(createMenuItemStyled("Italic", colour, Font.ITALIC));
            return subSubMenu;
        } else {
            JMenuItem menu = new JMenuItem(name);
            menu.addActionListener(new HighlightMenuListener(null, Font.PLAIN));
            return menu;
        }
    }

    private JMenuItem createMenuItemStyled(String name, Color colour, int style) {
        JMenuItem item = new JMenuItem(name);
        item.setFont(item.getFont().deriveFont(style));
        item.addActionListener(new HighlightMenuListener(colour, style));
        return item;
    }

    private class HighlightMenuListener implements ActionListener {

        private Highlight highlight;

        public HighlightMenuListener(Color colour, int style) {
            this.highlight = new Highlight(colour, style);
        }

        public void actionPerformed(ActionEvent e) {
            highlightTab(highlight);
        }

    }

}

class Highlight implements Serializable {

    boolean isNullColour;  // we use null colours to reset to the default, but java.awt.Color isn't serializable
    int colourRGB;
    int style;

    public Highlight(Color colour, int style) {
        this.colourRGB = colour == null ? 0 : colour.getRGB();
        isNullColour = colour == null;
        this.style = style;
    }

    public Color getColor() {
        return isNullColour ? null : new Color(colourRGB);
    }

    public int getStyle() {
        return style;
    }

    public String toString() {
        return getColor() + " " + style;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Highlight highlight = (Highlight) o;
        return isNullColour == highlight.isNullColour && colourRGB == highlight.colourRGB && style == highlight.style;
    }

    @Override
    public int hashCode() {
        return Objects.hash(isNullColour, colourRGB, style);
    }
}