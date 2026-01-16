import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useSEO } from "@/hooks/useSEO";
import {
  Wrench, 
  Paintbrush, 
  Plug, 
  Droplets, 
  Hammer, 
  Home,
  Sofa,
  Shield,
  Truck,
  Sparkles,
  ArrowRight,
  CheckCircle2
} from "lucide-react";

const serviceData = [
  {
    icon: Wrench,
    key: "repair",
    featuresKeys: ["ikea", "curtains", "shelves", "minor"],
  },
  {
    icon: Paintbrush,
    key: "painting",
    featuresKeys: ["walls", "decorative", "wallpaper", "restoration"],
  },
  {
    icon: Plug,
    key: "electrical",
    featuresKeys: ["outlets", "lighting", "diagnostics", "rewiring"],
  },
  {
    icon: Droplets,
    key: "plumbing",
    featuresKeys: ["installation", "leaks", "cleaning", "pipes"],
  },
  {
    icon: Hammer,
    key: "carpentry",
    featuresKeys: ["doors", "parquet", "custom", "restoration"],
  },
  {
    icon: Home,
    key: "renovation",
    featuresKeys: ["design", "rough", "finishing", "furnishing"],
  },
  {
    icon: Sofa,
    key: "furniture",
    featuresKeys: ["ikea", "kitchens", "wardrobes", "children"],
  },
  {
    icon: Shield,
    key: "security",
    featuresKeys: ["locks", "intercom", "cctv", "sensors"],
  },
  {
    icon: Truck,
    key: "moving",
    featuresKeys: ["packing", "transport", "disassembly", "assembly"],
  },
  {
    icon: Sparkles,
    key: "cleaning",
    featuresKeys: ["regular", "deep", "windows", "postConstruction"],
  },
];

const Services = () => {
  const { t } = useTranslation();
  useSEO();

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              {t("services.label")}
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto">
              {t("services.description")}
            </p>
          </div>
        </section>

        {/* Services Grid */}
        <section className="py-24 bg-background">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              {serviceData.map((service) => (
                <div
                  key={service.key}
                  className="group bg-card rounded-2xl p-8 shadow-card hover:shadow-card-hover transition-all duration-300"
                >
                  <div className="w-16 h-16 rounded-xl bg-accent/10 flex items-center justify-center mb-6 group-hover:bg-accent transition-colors">
                    <service.icon className="w-8 h-8 text-accent group-hover:text-accent-foreground transition-colors" />
                  </div>

                  <h3 className="text-xl font-semibold text-foreground mb-3">
                    {t(`services.items.${service.key}.title`)}
                  </h3>
                  <p className="text-muted-foreground text-sm mb-6 leading-relaxed">
                    {t(`services.items.${service.key}.description`)}
                  </p>

                  <ul className="space-y-2 mb-6">
                    {service.featuresKeys.map((featureKey) => (
                      <li key={featureKey} className="flex items-center gap-2 text-sm text-foreground">
                        <CheckCircle2 className="w-4 h-4 text-accent flex-shrink-0" />
                        {t(`services.features.${featureKey}`)}
                      </li>
                    ))}
                  </ul>

                  <div className="flex items-center justify-end pt-6 border-t border-border">
                    <Button variant="ghost" size="sm" asChild>
                      <Link to="/contact">
                        {t("services.order")}
                        <ArrowRight className="w-4 h-4 ml-1" />
                      </Link>
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-16 bg-secondary">
          <div className="container mx-auto px-4 text-center">
            <h2 className="text-2xl md:text-3xl font-bold text-foreground mb-4">
              {t("services.notFound.title")}
            </h2>
            <p className="text-muted-foreground mb-8">
              {t("services.notFound.description")}
            </p>
            <Button variant="accent" size="lg" asChild>
              <Link to="/contact">
                {t("services.notFound.cta")}
                <ArrowRight className="w-4 h-4 ml-2" />
              </Link>
            </Button>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default Services;