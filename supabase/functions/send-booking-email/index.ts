import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { Resend } from "https://esm.sh/resend@2.0.0";

const resend = new Resend(Deno.env.get("RESEND_API_KEY"));

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

// Simple in-memory rate limiting (per IP, resets on function cold start)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 5; // Max requests per window
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute window

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  
  if (entry.count >= RATE_LIMIT_MAX) {
    return true;
  }
  
  entry.count++;
  return false;
}

// HTML escape function to prevent XSS in email templates
function escapeHtml(str: string | undefined): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Input validation
function validateInput(data: BookingEmailRequest): { valid: boolean; error?: string } {
  if (!data.name || typeof data.name !== 'string' || data.name.trim().length === 0) {
    return { valid: false, error: 'Name is required' };
  }
  if (data.name.length > 100) {
    return { valid: false, error: 'Name is too long' };
  }
  
  if (!data.phone || typeof data.phone !== 'string' || data.phone.trim().length === 0) {
    return { valid: false, error: 'Phone is required' };
  }
  if (data.phone.length > 30) {
    return { valid: false, error: 'Phone number is too long' };
  }
  
  if (!data.service || typeof data.service !== 'string' || data.service.trim().length === 0) {
    return { valid: false, error: 'Service is required' };
  }
  if (data.service.length > 100) {
    return { valid: false, error: 'Service name is too long' };
  }
  
  if (data.email && typeof data.email === 'string') {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      return { valid: false, error: 'Invalid email format' };
    }
    if (data.email.length > 255) {
      return { valid: false, error: 'Email is too long' };
    }
  }
  
  if (data.message && data.message.length > 2000) {
    return { valid: false, error: 'Message is too long' };
  }
  
  if (data.date && data.date.length > 50) {
    return { valid: false, error: 'Date is too long' };
  }
  
  return { valid: true };
}

interface BookingEmailRequest {
  name: string;
  email: string;
  phone: string;
  service: string;
  date?: string;
  message?: string;
  urgent?: boolean;
}

const handler = async (req: Request): Promise<Response> => {
  // Handle CORS preflight requests
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Rate limiting check
    const clientIP = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || 
                     req.headers.get("cf-connecting-ip") || 
                     "unknown";
    
    if (isRateLimited(clientIP)) {
      console.warn(`Rate limit exceeded for IP: ${clientIP}`);
      return new Response(
        JSON.stringify({ error: "Too many requests. Please try again later." }),
        {
          status: 429,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }

    const requestData: BookingEmailRequest = await req.json();
    
    // Validate input
    const validation = validateInput(requestData);
    if (!validation.valid) {
      return new Response(
        JSON.stringify({ error: validation.error }),
        {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }

    const { name, email, phone, service, date, message, urgent } = requestData;

    // Escape all user inputs for HTML
    const safeName = escapeHtml(name);
    const safeEmail = escapeHtml(email);
    const safePhone = escapeHtml(phone);
    const safeService = escapeHtml(service);
    const safeDate = escapeHtml(date);
    const safeMessage = escapeHtml(message);

    const urgentLabel = urgent ? "⚡ СРОЧНАЯ ЗАЯВКА ⚡" : "Новая заявка";
    
    const emailHtml = `
      <h1>${urgentLabel}</h1>
      <h2>Детали заявки:</h2>
      <table style="border-collapse: collapse; width: 100%;">
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Имя:</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">${safeName}</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Телефон:</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">${safePhone}</td>
        </tr>
        ${safeEmail ? `
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Email:</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">${safeEmail}</td>
        </tr>
        ` : ''}
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Услуга:</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">${safeService}</td>
        </tr>
        ${safeDate ? `
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Дата:</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">${safeDate}</td>
        </tr>
        ` : ''}
        ${safeMessage ? `
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Сообщение:</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">${safeMessage}</td>
        </tr>
        ` : ''}
      </table>
      <p style="margin-top: 20px; color: #666;">
        Отправлено с сайта HandyMan Swiss
      </p>
    `;

    const emailResponse = await resend.emails.send({
      from: "TipTop Service <noreply@tiptop-service.ch>",
      to: ["tiptopch@proton.me"],
      subject: `${urgent ? "⚡ СРОЧНО: " : ""}Новая заявка от ${safeName}`,
      html: emailHtml,
    });

    console.log("Email sent successfully:", emailResponse);

    return new Response(JSON.stringify(emailResponse), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders,
      },
    });
  } catch (error: any) {
    console.error("Error in send-booking-email function:", error);
    return new Response(
      JSON.stringify({ error: "Failed to send booking request. Please try again later." }),
      {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      }
    );
  }
};

serve(handler);
