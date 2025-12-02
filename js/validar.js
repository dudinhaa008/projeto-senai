// SISTEMA DE PÁGINAS 
function showPage(pageId) {
    // Esconder todas as páginas
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Mostrar a página selecionada
    const targetPage = document.getElementById(pageId);
    if (targetPage) {
        targetPage.classList.add('active');
    }
    
    // Atualizar menu ativo
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.classList.remove('active');
    });
    
    // Rolar para o topo
    window.scrollTo(0, 0);
}

// MENU MOBILE 
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenu = document.querySelector('.mobile-menu');
    if (mobileMenu) {
        mobileMenu.addEventListener('click', function() {
            const navLinks = document.querySelector('.nav-links');
            if (navLinks) {
                navLinks.classList.toggle('active');
            }
        });
    }

    // DEMONSTRAÇÃO INTERATIVA 
    const steps = document.querySelectorAll('.step');
    const stepContents = document.querySelectorAll('.step-content');
    const prevBtn = document.getElementById('prev-step');
    const nextBtn = document.getElementById('next-step');
    
    let currentStep = 1;

    function updateSteps() {
        console.log('Atualizando passo:', currentStep);
        
        // Atualizar passos
        steps.forEach(step => {
            const stepNumber = parseInt(step.getAttribute('data-step'));
            if (stepNumber === currentStep) {
                step.classList.add('active');
            } else {
                step.classList.remove('active');
            }
        });

        // Atualizar conteúdos
        stepContents.forEach(content => {
            if (content.id === `step-${currentStep}`) {
                content.classList.add('active');
            } else {
                content.classList.remove('active');
            }
        });

        // Atualizar botões
        if (prevBtn) {
            prevBtn.disabled = currentStep === 1;
        }
        
        if (nextBtn) {
            nextBtn.disabled = currentStep === 4;
            
            if (currentStep === 4) {
                nextBtn.textContent = 'Finalizar';
            } else {
                nextBtn.textContent = 'Próximo';
            }
        }
    }

    // Botão Próximo
    if (nextBtn) {
        nextBtn.addEventListener('click', function() {
            if (currentStep < 4) {
                currentStep++;
                updateSteps();
            } else {
                alert('Demonstração concluída! Entre em contato para saber mais.');
                currentStep = 1;
                updateSteps();
            }
        });
    }

    // Botão Anterior
    if (prevBtn) {
        prevBtn.addEventListener('click', function() {
            if (currentStep > 1) {
                currentStep--;
                updateSteps();
            }
        });
    }

    // Clicar nos passos
    if (steps.length > 0) {
        steps.forEach(step => {
            step.addEventListener('click', function() {
                const stepNumber = parseInt(this.getAttribute('data-step'));
                currentStep = stepNumber;
                updateSteps();
            });
        });
    }

    // SISTEMA DE ABAS 
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    if (tabButtons.length > 0) {
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                // Remover active de todos
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                
                // Adicionar active no clicado
                this.classList.add('active');
                
                const tabId = this.getAttribute('data-tab');
                const tabContent = document.getElementById(tabId);
                if (tabContent) {
                    tabContent.classList.add('active');
                }
            });
        });
    }

    //  FORMULÁRIO DE CONTATO 
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const message = document.getElementById('message').value;
            
            if (name && email && message) {
                const submitBtn = this.querySelector('button[type="submit"]');
                const originalText = submitBtn.textContent;
                
                submitBtn.textContent = 'Enviando...';
                submitBtn.disabled = true;
                
                setTimeout(() => {
                    alert('Obrigado pelo seu interesse! Entraremos em contato em breve.');
                    this.reset();
                    submitBtn.textContent = originalText;
                    submitBtn.disabled = false;
                }, 1500);
            } else {
                alert('Por favor, preencha todos os campos obrigatórios.');
            }
        });
    }

    // FORMULÁRIO DE LOGIN 
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            
            if (email && password) {
                const submitBtn = this.querySelector('button[type="submit"]');
                const originalText = submitBtn.textContent;
                
                submitBtn.textContent = 'Entrando...';
                submitBtn.disabled = true;
                
                setTimeout(() => {
                    alert('Login realizado com sucesso! Redirecionando para o Dashboard...');
                    showPage('dashboard');
                    submitBtn.textContent = originalText;
                    submitBtn.disabled = false;
                }, 1500);
            } else {
                alert('Por favor, preencha todos os campos.');
            }
        });
    }

    //  FORMULÁRIO DE CONTATO DA PÁGINA 
    const contactFormPage = document.getElementById('contactFormPage');
    if (contactFormPage) {
        contactFormPage.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const name = document.getElementById('contact-name').value;
            const email = document.getElementById('contact-email').value;
            const message = document.getElementById('contact-message').value;
            
            if (name && email && message) {
                const submitBtn = this.querySelector('button[type="submit"]');
                const originalText = submitBtn.textContent;
                
                submitBtn.textContent = 'Enviando...';
                submitBtn.disabled = true;
                
                setTimeout(() => {
                    alert('Mensagem enviada com sucesso! Entraremos em contato em breve.');
                    this.reset();
                    submitBtn.textContent = originalText;
                    submitBtn.disabled = false;
                }, 1500);
            } else {
                alert('Por favor, preencha todos os campos obrigatórios.');
            }
        });
    }

    // BOTÕES DOS PLANOS 
    document.querySelectorAll('.pricing-card .btn').forEach(button => {
        button.addEventListener('click', function() {
            const planName = this.closest('.pricing-card').querySelector('h3').textContent;
            alert(`Você selecionou o plano: ${planName}`);
        });
    });

    // ROLAGEM SUAVE 
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 80,
                    behavior: 'smooth'
                });
                
                // Fechar menu mobile se estiver aberto
                const navLinks = document.querySelector('.nav-links');
                if (navLinks && navLinks.classList.contains('active')) {
                    navLinks.classList.remove('active');
                }
            }
        });
    });

    //  INICIALIZAR DEMONSTRAÇÃO
    if (steps.length > 0) {
        updateSteps();
    }

    console.log('JavaScript carregado com sucesso!');
});