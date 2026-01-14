import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { ChatWidget } from "@/components/chat/ChatWidget";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Star, Quote, ArrowRight, ThumbsUp } from "lucide-react";

const reviews = [
  {
    id: 1,
    nameKey: "anna",
    locationKey: "zurich",
    rating: 5,
    dateKey: "jan15",
    serviceKey: "bathroom",
    textKey: "review1",
    avatar: "AM",
    helpful: 12,
  },
  {
    id: 2,
    nameKey: "pierre",
    locationKey: "geneva",
    rating: 5,
    dateKey: "jan8",
    serviceKey: "ikea",
    textKey: "review2",
    avatar: "PD",
    helpful: 8,
  },
  {
    id: 3,
    nameKey: "thomas",
    locationKey: "bern",
    rating: 5,
    dateKey: "dec28",
    serviceKey: "renovation",
    textKey: "review3",
    avatar: "TS",
    helpful: 23,
  },
  {
    id: 4,
    nameKey: "sofia",
    locationKey: "lugano",
    rating: 5,
    dateKey: "dec20",
    serviceKey: "electrical",
    textKey: "review4",
    avatar: "SB",
    helpful: 15,
  },
  {
    id: 5,
    nameKey: "max",
    locationKey: "basel",
    rating: 4,
    dateKey: "dec10",
    serviceKey: "painting",
    textKey: "review5",
    avatar: "MW",
    helpful: 6,
  },
  {
    id: 6,
    nameKey: "elena",
    locationKey: "zug",
    rating: 5,
    dateKey: "dec1",
    serviceKey: "plumbing",
    textKey: "review6",
    avatar: "ER",
    helpful: 19,
  },
];

const Reviews = () => {
  const { t } = useTranslation();

  const stats = [
    { value: "500+", labelKey: "projects" },
    { value: "4.9", labelKey: "rating" },
    { value: "98%", labelKey: "satisfied" },
    { value: "10+", labelKey: "experience" },
  ];

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              {t("reviews.title")}
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto mb-12">
              {t("reviews.description")}
            </p>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto">
              {stats.map((stat) => (
                <div key={stat.labelKey} className="text-center">
                  <div className="text-3xl md:text-4xl font-bold text-accent mb-1">
                    {stat.value}
                  </div>
                  <div className="text-sm text-primary-foreground/70">
                    {t(`reviews.stats.${stat.labelKey}`)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Reviews */}
        <section className="py-24 bg-background">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {reviews.map((review) => (
                <div
                  key={review.id}
                  className="bg-card rounded-2xl p-8 shadow-card relative"
                >
                  <Quote className="absolute top-6 right-6 w-10 h-10 text-accent/20" />

                  {/* Header */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-4">
                      <div className="w-14 h-14 rounded-full bg-accent/10 flex items-center justify-center">
                        <span className="text-accent font-semibold text-lg">{review.avatar}</span>
                      </div>
                      <div>
                        <p className="font-semibold text-foreground">
                          {t(`reviews.reviewers.${review.nameKey}`)}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {t(`gallery.locations.${review.locationKey}`)}
                        </p>
                      </div>
                    </div>
                    <div className="flex">
                      {[...Array(5)].map((_, i) => (
                        <Star
                          key={i}
                          className={`w-5 h-5 ${
                            i < review.rating
                              ? "fill-accent text-accent"
                              : "text-muted"
                          }`}
                        />
                      ))}
                    </div>
                  </div>

                  {/* Service Badge */}
                  <div className="inline-block bg-secondary text-secondary-foreground text-xs font-medium px-3 py-1 rounded-full mb-4">
                    {t(`reviews.services.${review.serviceKey}`)}
                  </div>

                  {/* Text */}
                  <p className="text-foreground leading-relaxed mb-6">
                    "{t(`reviews.texts.${review.textKey}`)}"
                  </p>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-4 border-t border-border">
                    <span className="text-sm text-muted-foreground">
                      {t(`reviews.dates.${review.dateKey}`)}
                    </span>
                    <button className="flex items-center gap-2 text-sm text-muted-foreground hover:text-accent transition-colors">
                      <ThumbsUp className="w-4 h-4" />
                      {t("reviews.helpful")} ({review.helpful})
                    </button>
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
              {t("reviews.cta.title")}
            </h2>
            <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
              {t("reviews.cta.description")}
            </p>
            <Button variant="accent" size="lg" asChild>
              <Link to="/contact">
                {t("reviews.cta.button")}
                <ArrowRight className="w-4 h-4 ml-2" />
              </Link>
            </Button>
          </div>
        </section>
      </main>
      <Footer />
      <ChatWidget />
    </div>
  );
};

export default Reviews;