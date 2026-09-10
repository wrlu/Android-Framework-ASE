package net.wrlu.android.ase.components;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

public class ManifestParser {
    private static final Logger logger = LoggerFactory.getLogger(ManifestParser.class);

    public static PackageInfo parse(String manifestXml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(manifestXml)));
            Element manifest = doc.getDocumentElement();

            PackageInfo info = new PackageInfo();
            info.packageName = manifest.getAttribute("package");

            Element application = firstElement(manifest, "application");
            if (application == null) {
                logger.warn("Cannot get application tag in {}", info.packageName);
                return null;
            }

            info.definedPermissions = collectDefinedPermissions(manifest);
            info.usesPermissions = collectUsesPermissions(manifest);
            info.protectedBroadcasts = collectProtectedBroadcasts(manifest);

            List<Component> components = new ArrayList<>();
            components.addAll(collectActivities(application, info.packageName));
            components.addAll(collectServices(application, info.packageName));
            components.addAll(collectProviders(application, info.packageName));
            components.addAll(collectReceivers(application, info.packageName));
            info.components = components;

            return info;
        } catch (Exception e) {
            logger.error("Failed to parse manifest", e);
            return null;
        }
    }

    private static List<DefinedPermission> collectDefinedPermissions(Element manifest) {
        List<DefinedPermission> list = new ArrayList<>();
        NodeList perms = manifest.getElementsByTagName("permission");
        for (int i = 0; i < perms.getLength(); i++) {
            Element el = (Element) perms.item(i);
            DefinedPermission dp = new DefinedPermission();
            dp.name = el.getAttribute("android:name");
            dp.protectionLevel = el.getAttribute("android:protectionLevel");
            list.add(dp);
        }
        return list;
    }

    private static List<String> collectUsesPermissions(Element manifest) {
        List<String> list = new ArrayList<>();
        NodeList uses = manifest.getElementsByTagName("uses-permission");
        for (int i = 0; i < uses.getLength(); i++) {
            Element el = (Element) uses.item(i);
            list.add(el.getAttribute("android:name"));
        }
        return list;
    }

    private static List<String> collectProtectedBroadcasts(Element manifest) {
        List<String> list = new ArrayList<>();
        NodeList broadcasts = manifest.getElementsByTagName("protected-broadcast");
        for (int i = 0; i < broadcasts.getLength(); i++) {
            Element el = (Element) broadcasts.item(i);
            list.add(el.getAttribute("android:name"));
        }
        return list;
    }

    private static List<Component> collectActivities(Element application, String packageName) {
        List<Component> list = new ArrayList<>();
        NodeList nodes = application.getElementsByTagName("activity");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String name = el.getAttribute("android:name");
            if (name == null || name.isEmpty()) continue;
            if (isComponentExported(el)) {
                Component c = new Component();
                c.name = packageName + "/" + name;
                c.type = "activity";
                c.permission = el.getAttribute("android:permission");
                if (isActivityBrowsable(el)) {
                    c.intentFilters = collectIntentFilters(el);
                }
                list.add(c);
            }
        }
        return list;
    }

    private static List<Component> collectServices(Element application, String packageName) {
        List<Component> list = new ArrayList<>();
        NodeList nodes = application.getElementsByTagName("service");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String name = el.getAttribute("android:name");
            if (name == null || name.isEmpty()) continue;
            if (isComponentExported(el)) {
                Component c = new Component();
                c.name = packageName + "/" + name;
                c.type = "service";
                c.permission = el.getAttribute("android:permission");
                list.add(c);
            }
        }
        return list;
    }

    private static List<Component> collectProviders(Element application, String packageName) {
        List<Component> list = new ArrayList<>();
        NodeList nodes = application.getElementsByTagName("provider");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String name = el.getAttribute("android:name");
            if (name == null || name.isEmpty()) continue;
            if (isComponentExported(el)) {
                Component c = new Component();
                c.name = packageName + "/" + name;
                c.type = "provider";
                c.permission = el.getAttribute("android:permission");
                c.readPermission = el.getAttribute("android:readPermission");
                c.writePermission = el.getAttribute("android:writePermission");
                c.pathPermission = new ArrayList<>();

                NodeList pathPerms = el.getElementsByTagName("path-permission");
                for (int j = 0; j < pathPerms.getLength(); j++) {
                    Element pp = (Element) pathPerms.item(j);
                    String path = pp.getAttribute("android:path");
                    String pathPrefix = pp.getAttribute("android:pathPrefix");
                    String pathPattern = pp.getAttribute("android:pathPattern");
                    String perm = pp.getAttribute("android:permission");
                    String readPerm = pp.getAttribute("android:readPermission");
                    String writePerm = pp.getAttribute("android:writePermission");

                    PathPermission p = new PathPermission();
                    if (path != null && !path.isEmpty()) p.path = path;
                    if (pathPrefix != null && !pathPrefix.isEmpty()) p.pathPrefix = pathPrefix;
                    if (pathPattern != null && !pathPattern.isEmpty()) p.pathPattern = pathPattern;
                    if (perm != null && !perm.isEmpty()) p.permission = perm;
                    if (readPerm != null && !readPerm.isEmpty()) p.readPermission = readPerm;
                    if (writePerm != null && !writePerm.isEmpty()) p.writePermission = writePerm;
                    c.pathPermission.add(p);
                }
                list.add(c);
            }
        }
        return list;
    }

    private static List<Component> collectReceivers(Element application, String packageName) {
        List<Component> list = new ArrayList<>();
        NodeList nodes = application.getElementsByTagName("receiver");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String name = el.getAttribute("android:name");
            if (name == null || name.isEmpty()) continue;
            if (isComponentExported(el)) {
                Component c = new Component();
                c.name = packageName + "/" + name;
                c.type = "receiver";
                c.permission = el.getAttribute("android:permission");
                c.actions = getAllActionNames(el);
                list.add(c);
            }
        }
        return list;
    }

    private static List<String> getAllActionNames(Element component) {
        List<String> actions = new ArrayList<>();
        NodeList intentFilters = component.getElementsByTagName("intent-filter");
        for (int i = 0; i < intentFilters.getLength(); i++) {
            Element intentFilter = (Element) intentFilters.item(i);
            NodeList actionNodes = intentFilter.getElementsByTagName("action");
            for (int j = 0; j < actionNodes.getLength(); j++) {
                Element action = (Element) actionNodes.item(j);
                actions.add(action.getAttribute("android:name"));
            }
        }
        return actions;
    }

    private static boolean isComponentExported(Element component) {
        String exported = component.getAttribute("android:exported");
        if ("true".equals(exported)) return true;
        if ("false".equals(exported)) return false;
        return component.getElementsByTagName("intent-filter").getLength() > 0;
    }

    private static boolean isActivityBrowsable(Element activity) {
        if (!isComponentExported(activity)) return false;
        NodeList intentFilters = activity.getElementsByTagName("intent-filter");
        for (int i = 0; i < intentFilters.getLength(); i++) {
            Element intentFilter = (Element) intentFilters.item(i);
            NodeList categories = intentFilter.getElementsByTagName("category");
            for (int j = 0; j < categories.getLength(); j++) {
                Element category = (Element) categories.item(j);
                if ("android.intent.category.BROWSABLE".equals(category.getAttribute("android:name"))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<IntentFilter> collectIntentFilters(Element component) {
        List<IntentFilter> list = new ArrayList<>();
        NodeList intentFilters = component.getElementsByTagName("intent-filter");
        for (int i = 0; i < intentFilters.getLength(); i++) {
            Element ifEl = (Element) intentFilters.item(i);
            IntentFilter ifObj = new IntentFilter();

            ifObj.actions = new ArrayList<>();
            NodeList actions = ifEl.getElementsByTagName("action");
            for (int j = 0; j < actions.getLength(); j++) {
                ifObj.actions.add(((Element) actions.item(j)).getAttribute("android:name"));
            }

            ifObj.categories = new ArrayList<>();
            NodeList categories = ifEl.getElementsByTagName("category");
            for (int j = 0; j < categories.getLength(); j++) {
                ifObj.categories.add(((Element) categories.item(j)).getAttribute("android:name"));
            }

            ifObj.data = new ArrayList<>();
            NodeList dataNodes = ifEl.getElementsByTagName("data");
            for (int j = 0; j < dataNodes.getLength(); j++) {
                Element dEl = (Element) dataNodes.item(j);
                IntentData d = new IntentData();
                String scheme = dEl.getAttribute("android:scheme");
                if (!scheme.isEmpty()) d.scheme = scheme;
                String host = dEl.getAttribute("android:host");
                if (!host.isEmpty()) d.host = host;
                String port = dEl.getAttribute("android:port");
                if (!port.isEmpty()) d.port = port;
                String path = dEl.getAttribute("android:path");
                if (!path.isEmpty()) d.path = path;
                String pathPrefix = dEl.getAttribute("android:pathPrefix");
                if (!pathPrefix.isEmpty()) d.pathPrefix = pathPrefix;
                String pathPattern = dEl.getAttribute("android:pathPattern");
                if (!pathPattern.isEmpty()) d.pathPattern = pathPattern;
                String mimeType = dEl.getAttribute("android:mimeType");
                if (!mimeType.isEmpty()) d.mimeType = mimeType;
                ifObj.data.add(d);
            }
            list.add(ifObj);
        }
        return list;
    }

    private static Element firstElement(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) return (Element) nodes.item(0);
        return null;
    }
}
