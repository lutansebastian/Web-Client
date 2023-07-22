#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"
#include <ctype.h>

int main(int argc, char *argv[]) {
    
    //* Variabila folosita pentru a verifica daca un user este deja conectat
    //* sau nu.
    int user_logged = FALSE;

    //* Socketul pentru network communication
    int sockfd;

    //* String-uri pentru a salva cookie-ul primit la login.
    //* si token-ul primit la accesul in biblioteca (enter_library).
    char *cookie = NULL;
    char *token_jwt = NULL;

    //* Buffer pentru a salva comanda introdusa.
    char command[LINELEN];
    //* Variabila folosita doar pentru print.
    int command_status = GOOD;

    while (1) {
        //* Conditie folosita doar pentru print
        if (command_status == GOOD) {
            printf("Enter command: ");
        } else {
            printf("Try another command: ");
        }
        command_status = GOOD;

        memset(command, '\0', sizeof(command));
        fgets(command, sizeof(command), stdin);

        //* Verific ce comanda am primit
        if (!strcmp(command, "exit\n")) {
////////////////////////////////* EXIT *////////////////////////////////////////
            sleepy_print("Exiting process");
            break;
        } else if (!strcmp(command, "register\n")) {
////////////////////////////* REGISTRATION *////////////////////////////////////

            char username[1024];
            char password[1024];

            //* Pentru fiecare sir de caractere, aloc o dimensiune de 1024,
            //* iar dupa ce am terminat de scris, inlocuiesc caracterul '\n' cu
            //* terminatorul de sir '\0';
            printf("Enter username : ");
            fgets(username, 1024, stdin);
            username[strcspn(username, "\n")] = '\0';

            printf("Enter password : ");
            fgets(password, 1024, stdin);
            password[strcspn(password, "\n")] = '\0';

            sleepy_print("Registration process");
            printf ("Status : ");
            
            //* Verific daca numele sau parola contin spatii
            if (contains_spaces(username) || contains_spaces(password)) {
                printf("BAD\n");
                printf("Username or password contains spaces\n");
                printf("Please try again\n\n");
                continue;
            }

            //* Verific daca numele sau parola nu au fost introduse
            if (is_null_or_empty(username) || is_null_or_empty(password)) {
                printf("BAD\n");
                printf("Username or password is empty\n");
                printf("Please try again\n\n");
                continue;
            }

            //* Verific daca un user este deja conectat
            if (user_logged == TRUE) {
                printf("BAD\n");
                printf("You are already connected with an account\n");
                printf("Please, log out first!\n\n");
                continue;
            } else {
                //* Deschid conexiunea cu serverul 
                //* AF_INET pentru IPV4
                //* SOCK_STREAM, 0, pentru TCP
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                //* Initializez un obiect json si setez referinta catre value.
                JSON_Value *value = json_value_init_object();
                //* Extrag obiectul json din value
                JSON_Object *object = json_value_get_object(value);

                //* Adaug doua campuri in obiectu JSON cu numele username si
                //* password.
                json_object_set_string(object, "username", username);
                json_object_set_string(object, "password", password);

                //* Transform value intr-un sir de caractere in format JSON.
                char *serialized_string = json_serialize_to_string(value);

                //* Construiesc un mesaj de cerere HTTP POST
                char *message = compute_post_request(HOST, REGISTER, PAYLOAD_TYPE,
                    &serialized_string, 1, NULL, 0, NULL);
                
                //* Trimit mesajul la server prin intermediul socketului
                send_to_server(sockfd, message);

                //* Citesc raspunsul de la server prin intermediul unui socket
                char *response = receive_from_server(sockfd);

                //* Verific daca am primit vreo eroare in response.
                if (strstr(response, "error")) {
                    printf("BAD\n");
                    printf("Username already exists, try again\n");
                } else {
                    printf("GOOD\n");
                    printf("You have successfully registered\n");
                }

                //* Eliberez memodia si inchid socketul.
                json_value_free(value);
                json_free_serialized_string(serialized_string);
                
                free(message);
                free(response);

                close(sockfd);
            }
        } else if (!strcmp(command, "login\n")) {
////////////////////////////////* LOGIN *///////////////////////////////////////

            char username[1024];
            char password[1024];

            printf("Enter username : ");
            fgets(username, 1024, stdin);
            username[strcspn(username, "\n")] = '\0';

            printf("Enter password : ");
            fgets(password, 1024, stdin);
            password[strcspn(password, "\n")] = '\0';

            sleepy_print("Logging process");
            printf ("Status : ");

            if (contains_spaces(username) || contains_spaces(password)) {
                printf("BAD\n");
                printf("Username or password contains spaces\n");
                printf("Please try again\n\n");
                continue;
            }

            if (is_null_or_empty(username) || is_null_or_empty(password)) {
                printf("BAD\n");
                printf("Username or password is empty\n");
                printf("Please try again\n\n");
                continue;
            }

            if (user_logged == TRUE) {
                printf("BAD\n");
                printf("You are already connected with an account\n");
                printf("Please, log out first!\n\n");
                continue;
            }  else {
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                JSON_Value *value = json_value_init_object();
                JSON_Object *object = json_value_get_object(value);

                json_object_set_string(object, "username", username);
                json_object_set_string(object, "password", password);

                char *serialized_string = json_serialize_to_string(value);

                char *message = compute_post_request(HOST, LOGIN, PAYLOAD_TYPE,
                    &serialized_string, 1, NULL, 0, NULL);
                
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strstr(response, "error")) {
                    printf("BAD\n");
                    printf("The username or password is incorrect\n");
                } else {
                    //* Extrag din mesajul primit de la server, cookie-ul, care
                    //* reprezinta un string incepand cu connect.sid si se
                    //* termina cu ";".
                    char *start = strstr(response, "connect.sid");
                    char *stop = strstr(start, ";");

                    int length = stop - start;

                    //* Aloc memorie pentru acesta si copiez datele.
                    cookie = malloc(length + 1);
                    strncpy(cookie, start, length);

                    printf("GOOD\n");
                    printf("Here is your cookie : %s\n", cookie);
                    //* Marchez ca am un user conectat
                    user_logged = TRUE;
                }

                json_value_free(value);
                json_free_serialized_string(serialized_string);
                
                free(message);
                free(response);

                close(sockfd);
            }
        } else if (!strcmp(command, "enter_library\n")) {
////////////////////////////* ENTER LIBRARY *///////////////////////////////////

            sleepy_print("Entering library proccess");
            printf("Status : ");

            if (user_logged == FALSE) {
                printf("BAD\n");
                printf("You have to be connected\n");
                printf("Please, try again!\n\n");
                continue;
            } else if (token_jwt != NULL) {
                printf("BAD\n");
                printf("You have already entered the library\n\n");
                continue;
            } else {
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                //* Construiesc un mesaj de cerere HTTP GET
                char *message = compute_get_request(HOST, ACCESS, NULL, &cookie,
                                1, NULL);

                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                //* Extrag din mesajul primit de la server tokenul
                char *start = strstr(response, "{\"token\":\"");
                start += strlen("{\"token\":\"");
                char *stop = strstr(start, "\"");

                int length = stop - start;

                token_jwt = malloc(length + 1);
                strncpy(token_jwt, start, length);

                printf("GOOD\n");
                printf("Here is your token : %s\n", token_jwt);

                free(message);
                free(response);

                close(sockfd);
            }
        } else if (!strcmp(command, "get_books\n")) {
//////////////////////////////* GET BOOKS */////////////////////////////////////

            sleepy_print("Getting books proccess");
            printf("Status : ");

            if (user_logged == FALSE) {
                printf("BAD\n");
                printf("You have to be connected\n");
                printf("Please, try again!\n\n");
                continue;
            } else if (token_jwt == NULL){
                printf("BAD\n");
                printf("You don't have access to the library\n");
                printf("Enter the library and try again!\n\n");
                continue;
            } else {
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                char *message = compute_get_request(HOST, BOOKS, NULL, &cookie,
                                        1, token_jwt);

                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                printf("GOOD\n");
                printf("Here are the books:\n\n");

                char *books = strstr(response, "[");
                JSON_Value *value = json_parse_string(books);
                
                char *serialized_string = json_serialize_to_string_pretty(value);

                printf("%s\n", serialized_string);

                json_free_serialized_string(serialized_string);
                json_value_free(value);

                free(message);
                free(response);

                close(sockfd);
            }

        } else if (!strcmp(command, "get_book\n")) {
//////////////////////////////* GET BOOK *//////////////////////////////////////

            char id[1024];

            if (user_logged == FALSE) {
                sleepy_print("Getting book proccess");
                printf("Status : ");
                printf("BAD\n");
                printf("You have to be connected\n");
                printf("Please, try again!\n\n");
                continue;
            } else if (token_jwt == NULL){
                sleepy_print("Getting book proccess");
                printf("Status : ");
                printf("BAD\n");
                printf("You don't have access to the library\n");
                printf("Enter the library and try again!\n\n");
                continue;
            } else {
                printf("Introduce id-ul cartii : ");
                fgets(id, 1024, stdin);
                id[strcspn(id, "\n")] = '\0';

                sleepy_print("Getting book proccess");

                int is_all_digits = TRUE;
                for (int i = 0; id[i] != '\0'; i++) {
                    if (!isdigit(id[i])) {
                        is_all_digits = FALSE;
                        break;
                    }
                }

                if (is_null_or_empty(id) || is_all_digits == FALSE) {
                    printf("Status : ");
                    printf("BAD\n");
                    printf("The id is null or has a bad format\n");
                    printf("Please, try again!\n\n");
                    continue;
                }

                printf("Status : ");

                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
                //* Formez calea corespunzatoare pentru a extrage informatiile
                //* unei carti, concatenand la calea initiala, id-ului cartii.
                char *books_path = (char *) malloc(strlen(BOOKS) + strlen(id) + 1);
                strcpy(books_path, BOOKS);
                strcat(books_path, "/");
                strcat(books_path, id);

                char *message = compute_get_request(HOST, books_path, NULL, &cookie,
                                        1, token_jwt);

                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strstr(response, "error")) {
                    printf("BAD\n");
                    printf("The book was not found!\n");
                    printf("Please, try again!\n\n");
                    continue;
                }
                
                printf("GOOD\n");
                printf("Here are your book:\n\n");

                char *books = basic_extract_json_response(response);
                JSON_Value *value = json_parse_string(books);
                
                //* Pretty este folosit pentru a afisa informatiile cartii
                //* intr-un mod mai citet.
                char *serialized_string = json_serialize_to_string_pretty(value);

                printf("%s\n", serialized_string);

                json_free_serialized_string(serialized_string);
                json_value_free(value);

                free(message);
                free(response);
                free(books_path);

                close(sockfd);
            }
        } else if (!strcmp(command, "add_book\n")) {
//////////////////////////////* ADD BOOK *//////////////////////////////////////

            if (user_logged == FALSE) {
                sleepy_print("Adding book proccess");
                printf("Status : ");
                printf("BAD\n");
                printf("You have to be connected\n");
                printf("Please, try again!\n\n");
                continue;
            } else if (token_jwt == NULL){
                sleepy_print("Adding book proccess");
                printf("Status : ");
                printf("BAD\n");
                printf("You don't have access to the library\n");
                printf("Enter the library and try again!\n\n");
                continue;
            } else {
                char title[1024];
                char author[1024];
                char genre[1024];
                char page_count[1024];
                char publisher[1024];

                printf("Enter title : ");
                fgets(title, 1024, stdin);
                title[strcspn(title, "\n")] = '\0';

                printf("Enter author : ");
                fgets(author, 1024, stdin);
                author[strcspn(author, "\n")] = '\0';

                printf("Enter genre : ");
                fgets(genre, 1024, stdin);
                genre[strcspn(genre, "\n")] = '\0';

                printf("Enter number of pages : ");
                fgets(page_count, 1024, stdin);
                page_count[strcspn(page_count, "\n")] = '\0';

                printf("Enter publisher : ");
                fgets(publisher, 1024, stdin);
                publisher[strcspn(publisher, "\n")] = '\0';
                
                sleepy_print("Adding book proccess");
                printf("Status : ");

                int is_all_digits = TRUE;
                for (int i = 0; page_count[i] != '\0'; i++) {
                    if (!isdigit(page_count[i])) {
                        is_all_digits = FALSE;
                        break;
                    }
                }

                if (is_null_or_empty(title)) {
                    printf("BAD\n");
                    printf("Title is empty\n");
                    printf("Please, try again!\n\n");
                    continue;
                } else if (is_null_or_empty(author)) {
                    printf("BAD\n");
                    printf("Author is empty\n");
                    printf("Please, try again!\n\n");
                    continue;
                } else if (is_null_or_empty(genre)) {
                    printf("BAD\n");
                    printf("Genre is empty\n");
                    printf("Please, try again!\n\n");
                    continue;
                } else if (is_null_or_empty(page_count)) {
                    printf("BAD\n");
                    printf("Number of pages is empty\n");
                    printf("Please, try again!\n\n");
                    continue;
                } else if (is_all_digits == FALSE) {
                    printf("BAD\n");
                    printf("Number of pages has a bad format\n");
                    printf("Please, try again!\n\n");
                    continue;
                } else if (is_null_or_empty(publisher)) {
                    printf("BAD\n");
                    printf("Publisher is empty\n");
                    printf("Please, try again!\n\n");
                    continue;
                } 

                printf("GOOD\n");
                printf("You have successfully added the book!\n");

                JSON_Value *value = json_value_init_object();
                JSON_Object *object = json_value_get_object(value);

                json_object_set_string(object, "title", title);
                json_object_set_string(object, "author", author);
                json_object_set_string(object, "genre", genre);
                json_object_set_string(object, "page_count", page_count);
                json_object_set_string(object, "publisher", publisher);

                char *serialized_string = json_serialize_to_string(value);

                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                char *message = compute_post_request(HOST, BOOKS, PAYLOAD_TYPE,
                        &serialized_string, 1, NULL, 0, token_jwt);

                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                json_value_free(value);
                json_free_serialized_string(serialized_string);

                free(message);
                free(response);

                close(sockfd);
            }

        } else if (!strcmp(command, "delete_book\n")) {
//////////////////////////////* DELETE BOOK *///////////////////////////////////

            char id[1024];

            if (user_logged == FALSE) {
                sleepy_print("Deleting book proccess");
                printf("Status : ");
                printf("BAD\n");
                printf("You have to be connected\n");
                printf("Please, try again!\n\n");
                continue;
            } else if (token_jwt == NULL){
                sleepy_print("Deleting book proccess");
                printf("Status : ");
                printf("BAD\n");
                printf("You don't have access to the library\n");
                printf("Enter the library and try again!\n\n");
                continue;
            } else {

                printf("Introduce id-ul cartii : ");
                fgets(id, 1024, stdin);
                id[strcspn(id, "\n")] = '\0';

                sleepy_print("Deleting book proccess");

                int is_all_digits = TRUE;
                for (int i = 0; id[i] != '\0'; i++) {
                    if (!isdigit(id[i])) {
                        is_all_digits = FALSE;
                        break;
                    }
                }

                if (is_null_or_empty(id) || is_all_digits == FALSE) {
                    printf("Status : ");
                    printf("BAD\n");
                    printf("The id is null or has a bad format\n");
                    printf("Please, try again!\n\n");
                    continue;
                }

                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                char *books_path = (char *) malloc(strlen(BOOKS) + strlen(id) + 1);
                strcpy(books_path, BOOKS);
                strcat(books_path, "/");
                strcat(books_path, id);

                //* Construiesc un mesaj de cerere HTTP DELETE
                char *message = compute_delete_request(HOST, books_path, NULL, &cookie, 
                                            1, token_jwt);

                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strstr(response, "error")) {
                    printf("Status : ");
                    printf("BAD\n");
                    printf("The book was not found!\n");
                    printf("Please, try again!\n\n");
                    continue;
                }

                printf("Status : ");
                printf("GOOD\n");
                printf("The book with id: %s has been deleted\n", id);

                free(message);
                free(response);
                free(books_path);
                close(sockfd);
            }
        } else if (!strcmp(command, "logout\n")) {
////////////////////////////////* LOG OUT */////////////////////////////////////
            sleepy_print("Logging out proccess");
            printf("Status : ");

            if (user_logged == FALSE) {
                printf("BAD\n");
                printf("No user is currently logged in.\n\n");
                continue;
            } else {
                sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

                char *message = compute_get_request(HOST, LOGOUT, NULL, &cookie,
                                                        1, NULL);
                
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                user_logged = FALSE;

                printf("GOOD\n");
                printf("You have successfully logged out\n");

                free(message);
                free(response);

                //* Restez cookie-ul si token-ul pentru a nu mai fi valabile
                //* dupa un logout.
                if (cookie != NULL) {
                    free(cookie);
                    cookie = NULL;
                }

                if (token_jwt != NULL) {
                    free(token_jwt);
                    token_jwt = NULL;
                }

                close(sockfd);
            }
        } else {
            //* Cazul in care s-a introdus o comanda care nu exista
            printf("Command not found!\n");
            command_status = BAD;
        }
        printf("\n");
    }
    
    //* La terminarea programului, dupa introducerea comenzii exit, verific daca
    //* am alocat memorie pentru cookie sau token, iar in caz afirmativ, eliberez
    //* memoria
    if (cookie != NULL) {
        free(cookie);   
    }

    if (token_jwt != NULL) {
        free(token_jwt);
    }

    return 0;
}
