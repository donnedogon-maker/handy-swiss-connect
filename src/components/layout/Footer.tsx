import { Link } from "react-router-dom";
import { Wrench, Phone, Mail, MapPin, Clock, Facebook, Instagram, Linkedin } from "lucide-react";

export const Footer = () => {
  return (
    <footer className="bg-primary text-primary-foreground">
      <div className="container mx-auto px-4 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-10">
          {/* Brand */}
          <div>
            <Link to="/" className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 rounded-xl bg-accent flex items-center justify-center">
                <Wrench className="w-6 h-6 text-accent-foreground" />
              </div>
              <div>
                <span className="text-xl font-bold">HandyMan</span>
                <span className="block text-xs text-primary-foreground/70">Swiss Quality</span>
              </div>
            </Link>
            <p className="text-sm text-primary-foreground/70 leading-relaxed">
              Профессиональные услуги по ремонту и обслуживанию дома в Швейцарии. 
              Качество и надежность с 2010 года.
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="font-semibold mb-6">Быстрые ссылки</h4>
            <ul className="space-y-3">
              {[
                { name: "О нас", path: "/services" },
                { name: "Услуги", path: "/services" },
                { name: "Галерея работ", path: "/gallery" },
                { name: "Отзывы", path: "/reviews" },
                { name: "Контакты", path: "/contact" },
              ].map((link) => (
                <li key={link.name}>
                  <Link
                    to={link.path}
                    className="text-sm text-primary-foreground/70 hover:text-accent transition-colors"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact */}
          <div>
            <h4 className="font-semibold mb-6">Контакты</h4>
            <ul className="space-y-4">
              <li className="flex items-start gap-3">
                <Phone className="w-5 h-5 text-accent mt-0.5" />
                <div>
                  <a href="tel:+41791234567" className="text-sm hover:text-accent transition-colors">
                    +41 79 123 45 67
                  </a>
                </div>
              </li>
              <li className="flex items-start gap-3">
                <Mail className="w-5 h-5 text-accent mt-0.5" />
                <a href="mailto:info@handyman-swiss.ch" className="text-sm hover:text-accent transition-colors">
                  info@handyman-swiss.ch
                </a>
              </li>
              <li className="flex items-start gap-3">
                <MapPin className="w-5 h-5 text-accent mt-0.5" />
                <span className="text-sm text-primary-foreground/70">
                  Bahnhofstrasse 15<br />
                  8001 Zürich, Schweiz
                </span>
              </li>
            </ul>
          </div>

          {/* Hours */}
          <div>
            <h4 className="font-semibold mb-6">Часы работы</h4>
            <ul className="space-y-3">
              <li className="flex items-center gap-3">
                <Clock className="w-5 h-5 text-accent" />
                <span className="text-sm text-primary-foreground/70">
                  Пн-Пт: 08:00 - 18:00
                </span>
              </li>
              <li className="flex items-center gap-3 pl-8">
                <span className="text-sm text-primary-foreground/70">
                  Сб: 09:00 - 14:00
                </span>
              </li>
              <li className="flex items-center gap-3 pl-8">
                <span className="text-sm text-primary-foreground/70">
                  Вс: выходной
                </span>
              </li>
            </ul>
            <div className="flex gap-4 mt-6">
              <a href="#" className="w-10 h-10 rounded-full bg-primary-foreground/10 flex items-center justify-center hover:bg-accent transition-colors">
                <Facebook className="w-5 h-5" />
              </a>
              <a href="#" className="w-10 h-10 rounded-full bg-primary-foreground/10 flex items-center justify-center hover:bg-accent transition-colors">
                <Instagram className="w-5 h-5" />
              </a>
              <a href="#" className="w-10 h-10 rounded-full bg-primary-foreground/10 flex items-center justify-center hover:bg-accent transition-colors">
                <Linkedin className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>

        <div className="border-t border-primary-foreground/20 mt-12 pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-sm text-primary-foreground/60">
            © 2024 HandyMan Swiss. Все права защищены.
          </p>
          <div className="flex gap-6">
            <a href="#" className="text-sm text-primary-foreground/60 hover:text-accent transition-colors">
              Политика конфиденциальности
            </a>
            <a href="#" className="text-sm text-primary-foreground/60 hover:text-accent transition-colors">
              Условия использования
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};
