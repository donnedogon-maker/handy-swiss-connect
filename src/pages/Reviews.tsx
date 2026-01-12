import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { ChatWidget } from "@/components/chat/ChatWidget";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { Star, Quote, ArrowRight, ThumbsUp } from "lucide-react";

const reviews = [
  {
    id: 1,
    name: "Анна Мюллер",
    location: "Цюрих",
    rating: 5,
    date: "15 января 2024",
    service: "Реновация ванной",
    text: "Отличный сервис! Марко и его команда полностью обновили нашу ванную комнату. Работа была выполнена в срок и с высочайшим качеством. Очень пунктуальные и аккуратные мастера, убрали за собой всё до блеска.",
    avatar: "AM",
    helpful: 12,
  },
  {
    id: 2,
    name: "Пьер Дюбуа",
    location: "Женева",
    rating: 5,
    date: "8 января 2024",
    service: "Сборка кухни IKEA",
    text: "Заказывал сборку большой кухни IKEA. Работа выполнена безупречно — всё ровно, качественно закреплено. Мастер работал чисто и быстро. Рекомендую всем, кто ценит качество!",
    avatar: "PD",
    helpful: 8,
  },
  {
    id: 3,
    name: "Томас Шмидт",
    location: "Берн",
    rating: 5,
    date: "28 декабря 2023",
    service: "Полная реновация",
    text: "Полная реновация квартиры 80м² за 3 недели. Результат превзошёл все ожидания! От проектирования до финальной уборки — команда проявила высочайший профессионализм. Особая благодарность за соблюдение бюджета.",
    avatar: "TS",
    helpful: 23,
  },
  {
    id: 4,
    name: "София Бернаскони",
    location: "Лугано",
    rating: 5,
    date: "20 декабря 2023",
    service: "Электрика",
    text: "Срочно нужна была замена электрощитка. Приехали в тот же день, работу выполнили за 3 часа. Всё объяснили, показали, дали гарантию. Цена честная, качество отличное!",
    avatar: "SB",
    helpful: 15,
  },
  {
    id: 5,
    name: "Макс Вебер",
    location: "Базель",
    rating: 4,
    date: "10 декабря 2023",
    service: "Покраска квартиры",
    text: "Покрасили трёхкомнатную квартиру за 2 дня. Качество отличное, краски израсходовали экономно. Единственное — пришлось немного подождать из-за загруженности, но результат того стоил.",
    avatar: "MW",
    helpful: 6,
  },
  {
    id: 6,
    name: "Элена Росси",
    location: "Цуг",
    rating: 5,
    date: "1 декабря 2023",
    service: "Сантехника",
    text: "Устранили протечку в ванной, которую другие не могли найти месяц! Диагностика заняла 20 минут, ремонт — ещё час. Теперь всё работает идеально. Большое спасибо!",
    avatar: "ER",
    helpful: 19,
  },
];

const stats = [
  { value: "500+", label: "Выполненных проектов" },
  { value: "4.9", label: "Средняя оценка" },
  { value: "98%", label: "Довольных клиентов" },
  { value: "10+", label: "Лет опыта" },
];

const Reviews = () => {
  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="pt-20">
        {/* Hero */}
        <section className="py-20 bg-primary">
          <div className="container mx-auto px-4 text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-primary-foreground mb-6">
              Отзывы клиентов
            </h1>
            <p className="text-lg text-primary-foreground/80 max-w-2xl mx-auto mb-12">
              Мнение наших клиентов — лучшее подтверждение качества. 
              Читайте реальные отзывы о нашей работе.
            </p>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto">
              {stats.map((stat) => (
                <div key={stat.label} className="text-center">
                  <div className="text-3xl md:text-4xl font-bold text-accent mb-1">
                    {stat.value}
                  </div>
                  <div className="text-sm text-primary-foreground/70">{stat.label}</div>
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
                        <p className="font-semibold text-foreground">{review.name}</p>
                        <p className="text-sm text-muted-foreground">{review.location}</p>
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
                    {review.service}
                  </div>

                  {/* Text */}
                  <p className="text-foreground leading-relaxed mb-6">
                    "{review.text}"
                  </p>

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-4 border-t border-border">
                    <span className="text-sm text-muted-foreground">{review.date}</span>
                    <button className="flex items-center gap-2 text-sm text-muted-foreground hover:text-accent transition-colors">
                      <ThumbsUp className="w-4 h-4" />
                      Полезно ({review.helpful})
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
              Присоединяйтесь к довольным клиентам
            </h2>
            <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
              Закажите наши услуги и убедитесь в качестве лично!
            </p>
            <Button variant="accent" size="lg" asChild>
              <Link to="/contact">
                Записаться онлайн
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
