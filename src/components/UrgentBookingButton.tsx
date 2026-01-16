import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Zap, User, Phone, Mail, MessageSquare, Send, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

// Generate simple math captcha
const generateCaptcha = () => {
  const num1 = Math.floor(Math.random() * 10) + 1;
  const num2 = Math.floor(Math.random() * 10) + 1;
  return { num1, num2, answer: num1 + num2 };
};

const UrgentBookingButton = () => {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    phone: "",
    service: "",
    message: "",
  });
  const [captcha, setCaptcha] = useState(generateCaptcha());
  const [captchaInput, setCaptchaInput] = useState("");
  const [captchaError, setCaptchaError] = useState(false);

  const services = [
    t("contact.services.repair"),
    t("contact.services.painting"),
    t("contact.services.electrical"),
    t("contact.services.plumbing"),
    t("contact.services.carpentry"),
    t("contact.services.furniture"),
    t("contact.services.renovation"),
    t("contact.services.cleaning"),
    t("contact.services.other"),
  ];

  useEffect(() => {
    if (isOpen) {
      setCaptcha(generateCaptcha());
      setCaptchaInput("");
      setCaptchaError(false);
    }
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate captcha
    if (parseInt(captchaInput) !== captcha.answer) {
      setCaptchaError(true);
      setCaptcha(generateCaptcha());
      setCaptchaInput("");
      return;
    }
    
    setCaptchaError(false);
    setIsSubmitting(true);

    try {
      const { error } = await supabase.functions.invoke('send-booking-email', {
        body: {
          name: formData.name,
          email: formData.email,
          phone: formData.phone,
          service: formData.service,
          date: "",
          message: formData.message,
          urgent: true
        }
      });

      if (error) throw error;

      toast.success(t("urgent.success"), {
        description: t("urgent.successDescription"),
      });

      setFormData({
        name: "",
        email: "",
        phone: "",
        service: "",
        message: "",
      });
      setCaptchaInput("");
      setIsOpen(false);
    } catch (error) {
      console.error('Error sending email:', error);
      toast.error("Error sending request");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <>
      {/* Floating Urgent Button */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-24 right-6 z-50 group"
        aria-label={t("urgent.button")}
      >
        <div className="relative">
          {/* Pulsing rings */}
          <div className="absolute inset-0 rounded-full bg-destructive/30 animate-ping" />
          <div className="absolute -inset-2 rounded-full bg-destructive/20 animate-pulse" />
          <div className="absolute -inset-4 rounded-full bg-destructive/10 animate-pulse [animation-delay:150ms]" />
          
          {/* Main button */}
          <div className="relative flex items-center gap-2 bg-gradient-to-r from-destructive to-red-600 text-destructive-foreground px-5 py-3 rounded-full shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105">
            <Zap className="w-5 h-5 animate-pulse" />
            <span className="font-bold text-sm whitespace-nowrap">
              {t("urgent.button")}
            </span>
            <span className="bg-white/20 text-xs font-semibold px-2 py-0.5 rounded-full">
              24h
            </span>
          </div>
        </div>
      </button>

      {/* Urgent Booking Dialog */}
      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <div className="flex items-center gap-3 mb-2">
              <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
                <Zap className="w-6 h-6 text-destructive" />
              </div>
              <div>
                <DialogTitle className="text-xl font-bold text-foreground">
                  {t("urgent.title")}
                </DialogTitle>
                <p className="text-sm text-destructive font-medium">
                  {t("urgent.subtitle")}
                </p>
              </div>
            </div>
          </DialogHeader>

          {/* Urgent Banner */}
          <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4 mb-6">
            <p className="text-sm text-foreground">
              <span className="font-semibold text-destructive">{t("urgent.badge")}</span>{" "}
              {t("urgent.description")}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-foreground mb-2">
                  {t("contact.form.name")} *
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    required
                    placeholder={t("contact.form.namePlaceholder")}
                    className="w-full pl-10 pr-4 py-2.5 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-destructive focus:border-transparent text-sm"
                  />
                </div>
              </div>

              {/* Phone */}
              <div>
                <label className="block text-sm font-medium text-foreground mb-2">
                  {t("contact.form.phone")} *
                </label>
                <div className="relative">
                  <Phone className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <input
                    type="tel"
                    name="phone"
                    value={formData.phone}
                    onChange={handleChange}
                    required
                    placeholder="+41 79 813 51 47"
                    className="w-full pl-10 pr-4 py-2.5 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-destructive focus:border-transparent text-sm"
                  />
                </div>
              </div>

              {/* Email */}
              <div className="sm:col-span-2">
                <label className="block text-sm font-medium text-foreground mb-2">
                  {t("contact.form.email")}
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="example@mail.com"
                    className="w-full pl-10 pr-4 py-2.5 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-destructive focus:border-transparent text-sm"
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
                className="w-full px-4 py-2.5 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-destructive focus:border-transparent text-sm appearance-none"
              >
                <option value="">{t("contact.form.servicePlaceholder")}</option>
                {services.map((service) => (
                  <option key={service} value={service}>
                    {service}
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
                <MessageSquare className="absolute left-3 top-3 w-4 h-4 text-muted-foreground" />
                <textarea
                  name="message"
                  value={formData.message}
                  onChange={handleChange}
                  rows={3}
                  placeholder={t("contact.form.messagePlaceholder")}
                  className="w-full pl-10 pr-4 py-2.5 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-destructive focus:border-transparent resize-none text-sm"
                />
              </div>
            </div>

            {/* Captcha */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">
                {t("contact.form.captcha")} *
              </label>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 bg-secondary px-3 py-2.5 rounded-lg">
                  <ShieldCheck className="w-4 h-4 text-accent" />
                  <span className="font-bold text-foreground">
                    {captcha.num1} + {captcha.num2} = ?
                  </span>
                </div>
                <input
                  type="number"
                  value={captchaInput}
                  onChange={(e) => {
                    setCaptchaInput(e.target.value);
                    setCaptchaError(false);
                  }}
                  required
                  placeholder="?"
                  className={`w-20 px-3 py-2.5 bg-background border rounded-lg focus:outline-none focus:ring-2 focus:ring-destructive focus:border-transparent text-center font-bold ${
                    captchaError ? "border-destructive" : "border-border"
                  }`}
                />
              </div>
              {captchaError && (
                <p className="text-sm text-destructive mt-2">
                  {t("contact.form.captchaError")}
                </p>
              )}
            </div>

            <Button
              type="submit"
              className="w-full bg-gradient-to-r from-destructive to-red-600 hover:from-destructive/90 hover:to-red-700 text-white font-semibold py-3"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                t("contact.form.submitting")
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  {t("urgent.submit")}
                  <Send className="w-4 h-4 ml-2" />
                </>
              )}
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default UrgentBookingButton;