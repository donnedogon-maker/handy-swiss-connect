import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Star, Quote, ArrowRight } from "lucide-react";

const testimonials = [
  {
    nameKey: "Anna Müller",
    locationKey: "gallery.locations.zurich",
    rating: 5,
    textKey: "Excellent service! Marco fixed all the leaks in our bathroom in one visit. Very punctual and neat craftsman.",
    avatar: "AM",
  },
  {
    nameKey: "Pierre Dubois",
    locationKey: "gallery.locations.geneva",
    rating: 5,
    textKey: "Ordered IKEA kitchen assembly. The work was done flawlessly, everything is level and quality. Highly recommend!",
    avatar: "PD",
  },
  {
    nameKey: "Thomas Schmidt",
    locationKey: "gallery.locations.bern",
    rating: 5,
    textKey: "Complete apartment renovation in 3 weeks. The result exceeded expectations. True professionals!",
    avatar: "TS",
  },
];

export const TestimonialsSection = () => {
  const { t } = useTranslation();

  return (
    <section className="py-24 bg-secondary">
      <div className="container mx-auto px-4">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <span className="text-accent font-semibold text-sm uppercase tracking-wider">
            {t("testimonials.label")}
          </span>
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mt-3 mb-4">
            {t("testimonials.title")}
          </h2>
          <p className="text-muted-foreground">
            {t("testimonials.description")}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {testimonials.map((testimonial, index) => (
            <div
              key={testimonial.avatar}
              className="bg-card rounded-2xl p-8 shadow-card relative"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <Quote className="absolute top-6 right-6 w-10 h-10 text-accent/20" />
              
              <div className="flex mb-4">
                {[...Array(testimonial.rating)].map((_, i) => (
                  <Star key={i} className="w-5 h-5 fill-accent text-accent" />
                ))}
              </div>

              <p className="text-foreground mb-6 leading-relaxed">
                "{testimonial.textKey}"
              </p>

              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center">
                  <span className="text-accent font-semibold">{testimonial.avatar}</span>
                </div>
                <div>
                  <p className="font-semibold text-foreground">{testimonial.nameKey}</p>
                  <p className="text-sm text-muted-foreground">{t(testimonial.locationKey)}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="text-center mt-12">
          <Button variant="outline" size="lg" asChild>
            <Link to="/reviews">
              {t("testimonials.viewAll")}
              <ArrowRight className="w-4 h-4 ml-2" />
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
};
