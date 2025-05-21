//location.reload(); //Оновлення Сторінки.
//--------------------------------------------------------------------.
function validateForm() {
    const acceptAllCheckbox = document.getElementById("acceptAll");
    if (!acceptAllCheckbox.checked) {
        alert("You must accept all terms and conditions to sign up.");
        return false;
    }
    return true;
}
setTimeout(() => {
    const flashMessages = document.querySelectorAll(".flash-message");
    flashMessages.forEach(msg => {
        msg.style.transition = "opacity 0.5s";
        msg.style.opacity = "0"; // Зникає
        setTimeout(() => msg.remove(), 500); // Видаляє з DOM
    });
}, 3000); // Час затримки (3 секунди)
//[-----Налаштування рядка відправки повідомлення-----].
//Вставлення курсора автоматично та без приховання плейсхолдера.
window.addEventListener ("load", function() {
    document.getElementById ("inputField").focus();
});
//[--------Account--------].
function handleButtonClick(event) {
    const action = event.target.getAttribute("data-action"); // Отримуємо атрибут data-action

    const overlay = document.getElementById("overlay");
    const overlay3 = document.getElementById("overlay_3");
    const editContainer = document.getElementById("edit_container");
    const search_container = document.getElementById("search_container");
    const createContainer = document.getElementById ("create_chat_container");
    const settingsContainer = document.getElementById ("settings_menu_container")

    if (action === "open") {
        // Відкрити форму та overlay
        editContainer.style.display = "block";
        overlay.style.display = "block";
    } else if (action === "cancel") {
        // Закрити форму та overlay
        editContainer.style.display = "none";
        overlay.style.display = "none";
    } else if (action === "create-chat") {
        createContainer.style.display = "block";
        overlay.style.display = "block";
    } else if (action === "cancel") {
        createContainer.style.display = "none";
        overlay.style.display = "none";
    } else if (action === "settiongs_main") {
        document.body.style.overflow = "hidden";
        settingsContainer.style.display = "block";
        overlay.style.display = "block";
    } else if (action === "cancel1") {
        overlay3.style.display = "none";
        search_container.style.display = "none";
    } else if (action === "cancel3") {
        document.body.style.overflow = "auto";
        settingsContainer.style.display = "none";
        overlay.style.display = "none";
    }
}
//Додаємо обробник подій через делегування.
document.addEventListener ("click", handleButtonClick);
//Відкривання/закривання редагування чату.
function openEditChat (chatId) {
    // Припустимо, що всі контейнери сховані, і тепер показуємо тільки потрібний
    document.getElementById ('edit_chat_container_' + chatId).style.display = 'block';
    document.getElementById ('overlay').style.display = 'block';
}
function closeEditChat (chatId) {
    document.getElementById ('edit_chat_container_' + chatId).style.display = 'none';
    document.getElementById ('overlay').style.display = 'none';
}
//[--------Crete a new chat--------]
// Управління створенням нового чату
document.getElementById("photoInput").addEventListener("change", async function () {
    const file = this.files[0]; // Отримуємо вибраний файл

    if (!file) {
        alert("Please select a file.");
        return;
    }

    // Формуємо шлях для збереження
    const filePath = `static/images/${file.name}`; 
    console.log("Generated file path:", filePath);

    const formData = new FormData();
    formData.append("file", file); // Додаємо файл для завантаження
    formData.append("filePath", filePath); // Додаємо шлях для файлу

    try {
        const response = await fetch("/upload_photo", {
            method: "POST",
            body: formData,
        });

        if (response.ok) {
            const result = await response.json();
            alert("Photo uploaded successfully!");
            location.reload(); // Оновлення сторінки після завантаження
        } else {
            alert("Failed to upload photo.");
        }
    } catch (error) {
        console.error("Error during photo upload:", error);
    }
});
//[-----Налаштування меню головне-----].
//
function sendData(setting, value) {
    const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content");
    
    fetch("/update_setting", {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken
        },
        body: JSON.stringify({ setting: setting, value: value })
    })
    .then(response => response.json())
    .then(data => console.log("Server response:", data))
    .catch(error => console.error("Error:", error));
    // Затримка 4 секунди перед перезавантаженням сторінки
    setTimeout(() => {
        location.reload();
    }, 1000);
}
//
function showThinking() {
    document.getElementById ("addButton").disabled = true;
    const message = document.getElementById ("userMessage");
    const inputField = document.getElementById ("inputField"); // Отримуємо сам елемент
    const text = inputField.value.trim(); // Отримуємо його значення
    message.innerHTML = text; // Встановлюємо текст у `message`
    document.getElementById ("MessageBlock").style.display = "block"; // Показати анімацію
    // Виконуємо встановлення скролу через невелику затримку,
    // щоб елемент встиг оновитись
    setTimeout (function() {
        var container = document.querySelector (".scrollable-container3");
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    }, 200); // 100 мілісекунд, можна змінити за потребою
}
//Копіювання в буферобміну.
function copyAIMessage(msgIndex, elem) {
    // Зберігаємо початковий вміст кнопки
    var originalContent = elem.innerHTML;
    
    // SVG іконка, яку потрібно показувати після копіювання
    var newSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard2-check" viewBox="0 0 16 16">
                      <path d="M9.5 0a.5.5 0 0 1 .5.5.5.5 0 0 0 .5.5.5.5 0 0 1 .5.5V2a.5.5 0 0 1-.5.5h-5A.5.5 0 0 1 5 2v-.5a.5.5 0 0 1 .5-.5.5.5 0 0 0 .5-.5.5.5 0 0 1 .5-.5z"/>
                      <path d="M3 2.5a.5.5 0 0 1 .5-.5H4a.5.5 0 0 0 0-1h-.5A1.5 1.5 0 0 0 2 2.5v12A1.5 1.5 0 0 0 3.5 16h9a1.5 1.5 0 0 0 1.5-1.5v-12A1.5 1.5 0 0 0 12.5 1H12a.5.5 0 0 0 0 1h.5a.5.5 0 0 1 .5.5v12a.5.5 0 0 1-.5.5h-9a.5.5 0 0 1-.5-.5z"/>
                      <path d="M10.854 7.854a.5.5 0 0 0-.708-.708L7.5 9.793 6.354 8.646a.5.5 0 1 0-.708.708l1.5 1.5a.5.5 0 0 0 .708 0z"/>
                  </svg>`;

    // Формуємо новий вміст: повідомлення "Copied" і SVG. 
    // Можна додатково стилізувати через CSS або inline-стилі.
    var newContent = newSVG;

    // Замінюємо вміст кнопки на новий
    elem.innerHTML = newContent;
    
    // Копіюємо текст з відповідного блоку
    var messageElement = document.getElementById("ai-message-" + msgIndex);
    if (messageElement) {
        var textToCopy = messageElement.innerText;
        navigator.clipboard.writeText(textToCopy)
            .then(function() {
                // Якщо потрібно, додайте сповіщення (alert або інше)
            })
            .catch(function(err) {
                console.error('Помилка при копіюванні: ', err);
            });
    }
    
    // Через 2 секунди повертаємо початковий вміст кнопки
    setTimeout(function() {
        elem.innerHTML = originalContent;
    }, 2000);
}
function toggleThumb(elem) {
  // SVG-код незаповненої іконки (початковий стан)
  var unfilledSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-hand-thumbs-up" viewBox="0 0 16 16">
    <path d="M8.864.046C7.908-.193 7.02.53 6.956 1.466c-.072 1.051-.23 2.016-.428 2.59-.125.36-.479 1.013-1.04 1.639-.557.623-1.282 1.178-2.131 1.41C2.685 7.288 2 7.87 2 8.72v4.001c0 .845.682 1.464 1.448 1.545 1.07.114 1.564.415 2.068.723l.048.03c.272.165.578.348.97.484.397.136.861.217 1.466.217h3.5c.937 0 1.599-.477 1.934-1.064a1.86 1.86 0 0 0 .254-.912c0-.152-.023-.312-.077-.464.201-.263.38-.578.488-.901.11-.33.172-.762.004-1.149.069-.13.12-.269.159-.403.077-.27.113-.568.113-.857 0-.288-.036-.585-.113-.856a2 2 0 0 0-.138-.362 1.9 1.9 0 0 0 .234-1.734c-.206-.592-.682-1.1-1.2-1.272-.847-.282-1.803-.276-2.516-.211a10 10 0 0 0-.443.05 9.4 9.4 0 0 0-.062-4.509A1.38 1.38 0 0 0 9.125.111zM11.5 14.721H8c-.51 0-.863-.069-1.14-.164-.281-.097-.506-.228-.776-.393l-.04-.024c-.555-.339-1.198-.731-2.49-.868-.333-.036-.554-.29-.554-.55V8.72c0-.254.226-.543.62-.65 1.095-.3 1.977-.996 2.614-1.708.635-.71 1.064-1.475 1.238-1.978.243-.7.407-1.768.482-2.85.025-.362.36-.594.667-.518l.262.066c.16.04.258.143.288.255a8.34 8.34 0 0 1-.145 4.725.5.5 0 0 0 .595.644l.003-.001.014-.003.058-.014a9 9 0 0 1 1.036-.157c.663-.06 1.457-.054 2.11.164.175.058.45.3.57.65.107.308.087.67-.266 1.022l-.353.353.353.354c.043.043.105.141.154.315.048.167.075.37.075.581 0 .212-.027.414-.075.582-.05.174-.111.272-.154.315l-.353.353.353.354c.047.047.109.177.005.488a2.2 2.2 0 0 1-.505.805l-.353.353.353.354c.006.005.041.05.041.17a.9.9 0 0 1-.121.416c-.165.288-.503.56-1.066.56z"/>
  </svg>`;
  
  // SVG-код заповненої іконки (альтернативний стан)
  var filledSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-hand-thumbs-up-fill" viewBox="0 0 16 16">
    <path d="M6.956 1.745C7.021.81 7.908.087 8.864.325l.261.066c.463.116.874.456 1.012.965.22.816.533 2.511.062 4.51a10 10 0 0 1 .443-.051c.713-.065 1.669-.072 2.516.21.518.173.994.681 1.2 1.273.184.532.16 1.162-.234 1.733q.086.18.138.363c.077.27.113.567.113.856s-.036.586-.113.856c-.039.135-.09.273-.16.404.169.387.107.819-.003 1.148a3.2 3.2 0 0 1-.488.901c.054.152.076.312.076.465 0 .305-.089.625-.253.912C13.1 15.522 12.437 16 11.5 16H8c-.605 0-1.07-.081-1.466-.218a4.8 4.8 0 0 1-.97-.484l-.048-.03c-.504-.307-.999-.609-2.068-.722C2.682 14.464 2 13.846 2 13V9c0-.85.685-1.432 1.357-1.615.849-.232 1.574-.787 2.132-1.41.56-.627.914-1.28 1.039-1.639.199-.575.356-1.539.428-2.59z"/>
  </svg>`;
  
  // Перевіряємо, який стан зараз:
  if (elem.innerHTML.indexOf("bi-hand-thumbs-up-fill") !== -1) {
    // Якщо зараз заповнений, повертаємо незаповнений SVG.
    elem.innerHTML = unfilledSvg;
  } else {
    // Якщо зараз незаповнений, перемикаємо на заповнений SVG.
    elem.innerHTML = filledSvg;
  }
}
//
function ShowSearchContainer() {
// Отримуємо елементи з DOM
    const overlay_3 = document.getElementById("overlay_3");
    const searchContainer = document.getElementById("search_container");
    const searchInput = document.getElementById("search_input"); // Припускаємо, що тут саме input
    const listExample = document.getElementById("list-example"); // Контейнер результатів пошуку
    
// Очищаємо значення поля вводу та контейнер з чатами
    searchInput.value = "";
// Отримуємо критичне значення display
    listExample.innerHTML = "";
    const displayValue = window.getComputedStyle(searchContainer).display;

    // Перемикаємо відображення контейнера та overlay
    if (displayValue === "none") {
        searchContainer.style.display = "block";  // або "inline-block", залежно від дизайну
        overlay_3.style.display = "block";          // або "inline-block"
    } else {
        searchContainer.style.display = "none";
        overlay_3.style.display = "none";
    }
}
// Допоміжна функція для екранування символів, які мають спеціальне значення в regex
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function formatDate(dateString) {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
        return "Invalid date";
    }
    const year = date.getFullYear();
    const monthIndex = date.getMonth(); // 0 = January, 4 = May, etc.
    const day = date.getDate();
    
    // Масив скорочених назв місяців із двома літерами та крапкою
    const monthAbbr = ["Ja.", "Fe.", "Mr.", "Ap.", "Ma.", "Ju.", "Jl.", "Au.", "Se.", "Oc.", "No.", "De."];
    const formattedMonth = monthAbbr[monthIndex];
    const formattedDay = day < 10 ? "0" + day : day;
    
    return `${formattedDay} ${formattedMonth} ${year}`;
}

function SearchChat() {
    const searchValue = document.getElementById("search_input").value;
    const xhr = new XMLHttpRequest();
    xhr.open("GET", `/search_chat?search=${encodeURIComponent(searchValue)}`, true);
    
    xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300) {
            const result = JSON.parse(xhr.responseText);
            if (result.status === "nice") {
                const container = document.getElementById("list-example");
                let html = "";
                result.message.forEach(chat => {
                    // Створюємо регулярний вираз для пошукового запиту (без урахування регістру)
                    const re = new RegExp(escapeRegExp(searchValue), "gi");
                    // Виділення лише тієї частини, що збігається
                    const highlightedName = chat.name.replace(re, "<mark>$&</mark>");
                    
                    // Якщо chat.id валідний, генеруємо посилання, інакше звичайний блок
                    let linkStart = "";
                    let linkEnd = "";
                    if (chat.id !== undefined && chat.id !== null && chat.id !== "") { 
                        linkStart = `<a href="/choice_chat?chatid=${chat.id}" class="list_item list-group-item list-group-item-action">`;
                        linkEnd = `</a>`;
                    } else {
                        linkStart = `<div class="list_item list-group-item">`;
                        linkEnd = `</div>`;
                    }
                    
                    html += `
                        ${linkStart}
                            <div class="container_searched">
                                <h4>${highlightedName}</h4>
                                <h4 class="created_chad_some" style="margin: 0;">${formatDate(chat.date)}</h4>
                            </div>
                            <span class="color_searching" style="background-color: ${chat.color};"></span>
                        ${linkEnd}
                    `;
                });
                container.innerHTML = html;
            } else {
                alert("Server error: " + result.message);
            }
        } else {
            alert("Failed to search chat. Status: " + xhr.status);
        }
    };

    xhr.onerror = function () {
        alert("Error occurred while sending request.");
    };

    xhr.send();
}


// Функція, що відображає контейнер і перемикає іконки
function showContainer() {
    document.getElementById("overlay_2").style.display = "block";
    document.getElementById("container_1").style.display = "block";
    document.getElementById("icon-show").style.display = "none";
    document.getElementById("icon-hide").style.display = "inline-block";
}
// Функція, що ховає контейнер і перемикає іконки
function hideContainer() {
    if (window.innerWidth >= 1200) {
        document.getElementById("overlay_2").style.display = "none";
        document.getElementById("icon-show").style.display = "inline-block";
        document.getElementById("icon-hide").style.display = "none";
    } else {
        document.getElementById("overlay_2").style.display = "none";
        document.getElementById("container_1").style.display = "none";
        document.getElementById("icon-show").style.display = "inline-block";
        document.getElementById("icon-hide").style.display = "none";
    }
}
window.addEventListener("resize", function() {
    let container = document.getElementById("container_1");

    if (window.innerWidth >= 1200) {
        container.style.display = "block";
    } else if (window.innerWidth < 1200 && !container.classList.contains("manual-hide")) {
        container.style.display = "none";
    }
});

// Додаємо ручне ховання
document.getElementById("icon-hide").addEventListener("click", function() {
    let container = document.getElementById("container_1");
    container.style.display = "none";
    container.classList.add("manual-hide"); // Запам’ятовуємо, що контейнер ховали вручну
});

// При відкритті панелі очищуємо клас "manual-hide"
document.getElementById("icon-show").addEventListener("click", function() {
    let container = document.getElementById("container_1");
    container.style.display = "block";
    container.classList.remove("manual-hide");
});
//
