#define RCC_BASE            0x50000000

#define RCC_MP_APB1ENSETR   (*(volatile unsigned int *)(RCC_BASE + 0xA00))
#define RCC_MP_AHB4ENSETR   (*(volatile unsigned int *)(RCC_BASE + 0xA28))


#define GPIOD_BASE          0x50005000

#define GPIOD_MODER         (*(volatile unsigned int *)(GPIOD_BASE + 0x00))
#define GPIOD_AFRL          (*(volatile unsigned int *)(GPIOD_BASE + 0x20))


#define UART_BASE           0x40010000

#define USART_CR1           (*(volatile unsigned int *)(UART_BASE + 0x00))
#define USART_BRR           (*(volatile unsigned int *)(UART_BASE + 0x0C))
#define USART_ISR           (*(volatile unsigned int *)(UART_BASE + 0x1C))
#define USART_TDR           (*(volatile unsigned int *)(UART_BASE + 0x28))


void clock_init(void)
{
    // UART4 clock enable
    RCC_MP_APB1ENSETR = (1 << 16);

    // GPIOD clock enable
    RCC_MP_AHB4ENSETR = (1 << 3);
}


void gpio_uart_init(void)
{
    /*
       PD6 -> Alternate Function
       MODER:
       00 input
       01 output
       10 alternate
       11 analog
    */

    GPIOD_MODER &= ~(3 << 12);
    GPIOD_MODER |=  (2 << 12);


    /*
       AFRL pin6
       pin6 occupies bits 27:24
       AF6 = UART4_TX
    */

    GPIOD_AFRL &= ~(0xF << 24);
    GPIOD_AFRL |=  (6 << 24);
}


void uart_init(void)
{
    // Disable USART
    USART_CR1 = 0;


    /*
       UART clock assumed 64MHz
       64000000 / 115200 = 555
    */

    USART_BRR = 555;


    /*
       CR1:
       bit0 UE enable
       bit3 TE transmitter enable
    */

    USART_CR1 = (1 << 0) | (1 << 3);
}


void uart_putc(char c)
{
    // wait TX empty
    while(!(USART_ISR & (1 << 7)))
    {
    }

    USART_TDR = c;
}


void uart_puts(char *s)
{
    while(*s)
    {
        uart_putc(*s++);
    }
}


void delay(void)
{
    for(volatile unsigned int i=0;i<10000000;i++)
    {
        ;
    }
}


int main(void)
{
    clock_init();

    gpio_uart_init();

    uart_init();


    uart_puts("\r\n");
    uart_puts("====================\r\n");
    uart_puts("Secure Manager Start\r\n");
    uart_puts("====================\r\n");


    delay();

    return 0;
}
