import {
  Activity,
  Bell,
  Box,
  ClipboardList,
  HelpCircle,
  LayoutDashboard,
  Monitor,
  Network,
  Settings,
  ShieldCheck,
  Terminal,
  Users,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import { useT } from "../i18n";
type Link = { route: string; label: string; icon: LucideIcon };
const sections: { title: string; links: Link[] }[] = [
  {
    title: "dashboardSection",
    links: [
      { route: "overview", label: "overview", icon: LayoutDashboard },
      { route: "alerts", label: "alerts", icon: Bell },
      { route: "system-health", label: "system-health", icon: Activity },
    ],
  },
  {
    title: "windowsSection",
    links: [
      { route: "devices", label: "devices", icon: Monitor },
      { route: "device-groups", label: "device-groups", icon: Users },
      { route: "owners", label: "owners", icon: Users },
    ],
  },
  {
    title: "networkSection",
    links: [
      { route: "explorer", label: "explorer", icon: Network },
      { route: "admission", label: "adm.title", icon: ShieldCheck },
      { route: "network-overview", label: "network-overview", icon: Network },
      { route: "access-points", label: "access-points", icon: Wifi },
      { route: "ap-groups", label: "ap-groups", icon: Users },
      { route: "topology", label: "topology", icon: Network },
      { route: "connected-clients", label: "connected-clients", icon: Wifi },
      { route: "network-inventory", label: "network-inventory", icon: Network },
      { route: "diagnostics", label: "diagnostics", icon: Activity },
      { route: "network", label: "dhcpManagement", icon: Network },
    ],
  },
  {
    title: "policies",
    links: [
      { route: "policies", label: "policies", icon: ShieldCheck },
      { route: "policy-layers", label: "policyLayers", icon: ShieldCheck },
    ],
  },
  {
    title: "deploymentSection",
    links: [
      { route: "software", label: "software", icon: Box },
      { route: "deployments", label: "deployments", icon: Box },
    ],
  },
  {
    title: "remoteSection",
    links: [
      { route: "sessions", label: "sessions", icon: Terminal },
      {
        route: "maintenance-jobs",
        label: "maintenance-jobs",
        icon: ClipboardList,
      },
    ],
  },
  {
    title: "monitoringSection",
    links: [
      { route: "incidents", label: "incidents", icon: Activity },
      { route: "audit", label: "audit", icon: ClipboardList },
    ],
  },
  {
    title: "settings",
    links: [
      { route: "administrators", label: "administrators", icon: Users },
      {
        route: "monitoring-settings",
        label: "monitoring-settings",
        icon: Activity,
      },
      {
        route: "recovery-settings",
        label: "recovery-settings",
        icon: Settings,
      },
      { route: "settings", label: "languageAndSecurity", icon: Settings },
    ],
  },
];
export function Navigation({ page }: { page: string }) {
  const t = useT();
  return (
    <div className="grouped-navigation">
      {sections.map((section, i) => (
        <details
          className="nav-group"
          key={i}
          open={section.links.some((l) => l.route === page) || i < 3}
        >
          <summary>{t(section.title)}</summary>
          <nav>
            {section.links.map((link) => (
              <a
                key={link.route}
                href={"#" + link.route}
                className={link.route === page ? "active" : ""}
              >
                <link.icon size={17} />
                <span>{t(link.label)}</span>
              </a>
            ))}
          </nav>
        </details>
      ))}
      <nav>
        <a href="#help" className={page === "help" ? "active" : ""}>
          <HelpCircle size={18} />
          <span>{t("helpCenter")}</span>
        </a>
      </nav>
    </div>
  );
}
