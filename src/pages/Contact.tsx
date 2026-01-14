import { useState } from "react";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { ChatWidget } from "@/components/chat/ChatWidget";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";
import { 
  Phone, 
  Mail, 
  MapPin, 
  Clock, 
  Send,
  CheckCircle2,
  Calendar,
  User,
  MessageSquare
} from "lucide-react";
import { toast } from "sonner";

const serviceKeys = ["repair", "painting", "electrical", "plumbing", "carpentry", "furniture", "renovation", "other"];

const Contact = () => {
  const { t } = useTranslation();
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    phone: "",
    service: "",
    date: "",
    message: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    // Simulate submission
    await new Promise((resolve) => setTimeout(resolve, 1500));

    toast.success(t("contact.form.success"), {
      description: t("contact.form.successDescription"),
    });

    setFormData({
      name: "",
      email: "",
      phone: "",
      service: "",
      date: "",
      message: "",
    });
    setIsSubmitting(false);
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const benefits = [
    t("contact.benefits.estimate"),
    t("contact.benefits.response"),
    t("contact.benefits.warranty"),
    t("contact.benefits.fixed"),
  ];

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              {t("contact.title")}
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto">
              {t("contact.description")}
            </p>
          </div>
        </section>

        {/* Content */}
        <section className="py-24 bg-background">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
              {/* Contact Info */}
              <div className="space-y-8">
                <div>
                  <h2 className="text-2xl font-bold text-foreground mb-6">
                    {t("contact.info.title")}
                  </h2>
                  <div className="space-y-6">
                    <a
                      href="tel:+41798135147"
                      className="flex items-start gap-4 group"
                    >
                      <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center group-hover:bg-accent transition-colors">
                        <Phone className="w-5 h-5 text-accent group-hover:text-accent-foreground transition-colors" />
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">{t("contact.info.phone")}</p>
                        <p className="font-semibold text-foreground group-hover:text-accent transition-colors">
                          +41 79 813 51 47
                        </p>
                      </div>
                    </a>

                    <a
                      href="mailto:info@handyman-swiss.ch"
                      className="flex items-start gap-4 group"
                    >
                      <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center group-hover:bg-accent transition-colors">
                        <Mail className="w-5 h-5 text-accent group-hover:text-accent-foreground transition-colors" />
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">{t("contact.info.email")}</p>
                        <p className="font-semibold text-foreground group-hover:text-accent transition-colors">
                          info@handyman-swiss.ch
                        </p>
                      </div>
                    </a>

                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center">
                        <MapPin className="w-5 h-5 text-accent" />
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">{t("contact.info.address")}</p>
                        <p className="font-semibold text-foreground">
                          Bahnhofstrasse 15<br />
                          8001 Zürich
                        </p>
                      </div>
                    </div>

                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 rounded-xl bg-accent/10 flex items-center justify-center">
                        <Clock className="w-5 h-5 text-accent" />
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">{t("contact.info.hours")}</p>
                        <p className="font-semibold text-foreground">
                          {t("contact.info.weekdays")}<br />
                          {t("contact.info.saturday")}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Benefits */}
                <div className="bg-secondary rounded-2xl p-6">
                  <h3 className="font-semibold text-foreground mb-4">{t("contact.benefits.title")}</h3>
                  <ul className="space-y-3">
                    {benefits.map((item) => (
                      <li key={item} className="flex items-center gap-3 text-sm text-foreground">
                        <CheckCircle2 className="w-5 h-5 text-accent flex-shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Booking Form */}
              <div className="lg:col-span-2">
                <div className="bg-card rounded-2xl p-8 shadow-card">
                  <h2 className="text-2xl font-bold text-foreground mb-2">
                    {t("contact.form.title")}
                  </h2>
                  <p className="text-muted-foreground mb-8">
                    {t("contact.form.description")}
                  </p>

                  <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* Name */}
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-2">
                          {t("contact.form.name")} *
                        </label>
                        <div className="relative">
                          <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                          <input
                            type="text"
                            name="name"
                            value={formData.name}
                            onChange={handleChange}
                            required
                            placeholder={t("contact.form.namePlaceholder")}
                            className="w-full pl-12 pr-4 py-3 bg-background border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                          />
                        </div>
                      </div>

                      {/* Phone */}
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-2">
                          {t("contact.form.phone")} *
                        </label>
                        <div className="relative">
                          <Phone className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                          <input
                            type="tel"
                            name="phone"
                            value={formData.phone}
                            onChange={handleChange}
                            required
                            placeholder="+41 79 813 51 47"
                            className="w-full pl-12 pr-4 py-3 bg-background border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                          />
                        </div>
                      </div>

                      {/* Email */}
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-2">
                          {t("contact.form.email")}
                        </label>
                        <div className="relative">
                          <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                          <input
                            type="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            placeholder="example@mail.com"
                            className="w-full pl-12 pr-4 py-3 bg-background border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                          />
                        </div>
                      </div>

                      {/* Date */}
                      <div>
                        <label className="block text-sm font-medium text-foreground mb-2">
                          {t("contact.form.date")}
                        </label>
                        <div className="relative">
                          <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                          <input
                            type="date"
                            name="date"
                            value={formData.date}
                            onChange={handleChange}
                            className="w-full pl-12 pr-4 py-3 bg-background border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Service */}
                    <div>
                      <label className="block text-sm font-medium text-foreground mb-2">
                        {t("contact.form.service")} *
                      </label>
                      <select
                        name="service"
                        value={formData.service}
                        onChange={handleChange}
                        required
                        className="w-full px-4 py-3 bg-background border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent appearance-none"
                      >
                        <option value="">{t("contact.form.servicePlaceholder")}</option>
                        {serviceKeys.map((key) => (
                          <option key={key} value={key}>
                            {t(`contact.services.${key}`)}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Message */}
                    <div>
                      <label className="block text-sm font-medium text-foreground mb-2">
                        {t("contact.form.message")}
                      </label>
                      <div className="relative">
                        <MessageSquare className="absolute left-4 top-4 w-5 h-5 text-muted-foreground" />
                        <textarea
                          name="message"
                          value={formData.message}
                          onChange={handleChange}
                          rows={4}
                          placeholder={t("contact.form.messagePlaceholder")}
                          className="w-full pl-12 pr-4 py-3 bg-background border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent resize-none"
                        />
                      </div>
                    </div>

                    <Button
                      type="submit"
                      variant="accent"
                      size="xl"
                      className="w-full"
                      disabled={isSubmitting}
                    >
                      {isSubmitting ? (
                        t("contact.form.submitting")
                      ) : (
                        <>
                          {t("contact.form.submit")}
                          <Send className="w-5 h-5 ml-2" />
                        </>
                      )}
                    </Button>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Map Placeholder */}
        <section className="h-96 bg-muted relative">
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <MapPin className="w-12 h-12 text-accent mx-auto mb-4" />
              <p className="text-lg font-semibold text-foreground">Bahnhofstrasse 15, 8001 Zürich</p>
              <p className="text-muted-foreground">{t("contact.map")}</p>
            </div>
          </div>
        </section>
      </main>
      <Footer />
      <ChatWidget />
    </div>
  );
};

export default Contact;