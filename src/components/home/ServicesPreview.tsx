import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { 
  Wrench, 
  Paintbrush, 
  Plug, 
  Droplets, 
  Hammer, 
  Home,
  ArrowRight 
} from "lucide-react";

export const ServicesPreview = () => {
  const { t } = useTranslation();

  const services = [
    {
      icon: Wrench,
      titleKey: "services.items.repair.title",
      descriptionKey: "services.items.repair.description",
    },
    {
      icon: Paintbrush,
      titleKey: "services.items.painting.title",
      descriptionKey: "services.items.painting.description",
    },
    {
      icon: Plug,
      titleKey: "services.items.electrical.title",
      descriptionKey: "services.items.electrical.description",
    },
    {
      icon: Droplets,
      titleKey: "services.items.plumbing.title",
      descriptionKey: "services.items.plumbing.description",
    },
    {
      icon: Hammer,
      titleKey: "services.items.carpentry.title",
      descriptionKey: "services.items.carpentry.description",
    },
    {
      icon: Home,
      titleKey: "services.items.renovation.title",
      descriptionKey: "services.items.renovation.description",
    },
  ];

  return (
    <section className="py-24 bg-background">
      <div className="container mx-auto px-4">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <span className="text-accent font-semibold text-sm uppercase tracking-wider">
            {t("services.label")}
          </span>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mt-3 mb-4">
            {t("services.title")}
          </h2>
          <p className="text-muted-foreground">
            {t("services.description")}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {services.map((service, index) => (
            <div
              key={service.titleKey}
              className="group bg-card rounded-2xl p-8 shadow-card hover:shadow-card-hover transition-all duration-300 hover:-translate-y-1"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="w-14 h-14 rounded-xl bg-accent/10 flex items-center justify-center mb-6 group-hover:bg-accent group-hover:scale-110 transition-all duration-300">
                <service.icon className="w-7 h-7 text-accent group-hover:text-accent-foreground transition-colors" />
              </div>
              <h3 className="text-xl font-semibold text-foreground mb-3">
                {t(service.titleKey)}
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                {t(service.descriptionKey)}
              </p>
            </div>
          ))}
        </div>

        <div className="text-center mt-12">
          <Button variant="outline" size="lg" asChild>
            <Link to="/services">
              {t("services.viewAll")}
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
};
