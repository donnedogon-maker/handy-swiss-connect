import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Phone, Clock, CheckCircle2 } from "lucide-react";

export const CTASection = () => {
  const { t } = useTranslation();

  return (
    <section className="py-24 bg-primary relative overflow-hidden">
      {/* Decorative elements */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-accent/10 rounded-full blur-3xl" />
      <div className="absolute bottom-0 left-0 w-64 h-64 bg-accent/10 rounded-full blur-3xl" />

      <div className="container mx-auto px-4 relative z-10">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-primary-foreground mb-6">
            {t("cta.title")}
          </h2>
          <p className="text-lg text-primary-foreground/80 mb-10 max-w-2xl mx-auto">
            {t("cta.description")}
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Button variant="hero" size="xl" asChild>
              <Link to="/contact">{t("cta.book")}</Link>
            </Button>
            <Button variant="hero-outline" size="xl" asChild>
              <a href="tel:+41791234567">
                <Phone className="w-5 h-5 mr-2" />
                +41 79 123 45 67
              </a>
            </Button>
          </div>

          <div className="flex flex-wrap justify-center gap-8">
            <div className="flex items-center gap-2 text-primary-foreground/80">
              <CheckCircle2 className="w-5 h-5 text-accent" />
              <span>{t("cta.estimate")}</span>
            </div>
            <div className="flex items-center gap-2 text-primary-foreground/80">
              <Clock className="w-5 h-5 text-accent" />
              <span>{t("cta.response")}</span>
            </div>
            <div className="flex items-center gap-2 text-primary-foreground/80">
              <CheckCircle2 className="w-5 h-5 text-accent" />
              <span>{t("cta.quality")}</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
