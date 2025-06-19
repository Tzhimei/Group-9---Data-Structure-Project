#include <iostream>
#include <fstream>
#include <string>
#include <functional>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <conio.h>
#include <ctime>
#include <chrono>
using namespace std;
const int MAX_USERS = 1000;
const string SUPERADMIN_FILE = "superadmin.txt";
const string ADMIN_FILE = "admin.txt";
const string BOOK_FILE = "book.txt";
const string USER_FILE = "user.txt";
const string BORROW_FILE = "borrow.txt";
const string RETURN_FILE = "return.txt";
const string SUMMARY_REPORT_FILE = "summary_report.txt";
const string OVERDUE_REPORT_FILE = "overdue_report.txt";
const string reportFilename = "user_summary_report.txt";
const int MAX_CATEGORIES = 100;
const int MAX_POPULAR_BOOKS = 100;
const int MAX_BORROW_RECORDS = 1000;
enum Role { SUPERADMIN, ADMIN, REGULAR_USER };
const int TABLE_SIZE = 100;
const int MAX_BOOKS = 100;
const int MAX_ADMINS = 100;
const int MAX_COPIES = 10;
struct SystemStats 
{
    int userCount;
    int adminCount;
    int superAdminCount;
};
struct LibraryConfig 
{
    string libraryName;
    int maxBorrowDays;
    double finePerDay;
};
struct AuditLog 
{
    string username;
    string action;
    string timestamp;
};
struct PopularBook 
{
    string isbn;
    string title;
    int borrowCount;
};
struct CategoryStats 
{
    string category;
    int bookCount;
    int availableCount;
};
struct ReportData
{
    int totalBooks;
    int availableBooks;
    int borrowedBooks;
    string generationTime;
};
struct BorrowRecord {
    string isbn;
    string borrowTimeStr;
    string title;
};
class LibraryEntity 
{
protected:
    string id;
public:
    LibraryEntity(string i) : id(i) {}
    virtual ~LibraryEntity() {}
    virtual void display() const = 0;
    string getId() const { return id; }
};
class TimestampEntity 
{
protected:
    string creationTime;
public:
    TimestampEntity() 
    {
        time_t now = time(0);
        creationTime = ctime(&now);
    }
    string getCreationTime() const { return creationTime; }
};
class Book : public LibraryEntity, public TimestampEntity 
{
private:
    string title;
    string author;
    int year;
    string category;
    bool isBorrowed;
    string borrowedBy;
    string lastActionTime;
    Book* next;
    int copyNumber;
    int totalCopies;
    int borrowedCopies;
public:
    Book(string i, string t, string a, int y, string c, int copy = 1)
	    : LibraryEntity(i), title(t), author(a), year(y), category(c),
	      isBorrowed(false), borrowedBy(""), lastActionTime(""), 
	      copyNumber(copy), totalCopies(copy), borrowedCopies(0), next(nullptr) {}
    ~Book() override {}
    void display() const override 
    {
        cout << "ISBN: " << id << " (Copy " << copyNumber << ")\nTitle: " << title 
             << "\nAuthor: " << author << "\nYear: " << year
             << "\nCategory: " << category << "\nStatus: " 
             << (isBorrowed ? "Borrowed by " + borrowedBy : "Available") 
             << "\nCreated: " << creationTime << endl;
    }
    friend void updateBookStatus(Book& book, bool status, const string& user);
    friend void logBookAction(Book& book, const string& action);
    string getTitle() const { return title; }
    string getAuthor() const { return author; }
    int getYear() const { return year; }
    string getCategory() const { return category; }
    bool getIsBorrowed() const { return isBorrowed; }
    string getBorrowedBy() const { return borrowedBy; }
    string getLastActionTime() const { return lastActionTime; }
    int getTotalCopies() const { return totalCopies; }
    int getBorrowedCopies() const { return borrowedCopies; }
    Book* getNext() const { return next; }
    
    void setTitle(const string& t) { title = t; }
    void setAuthor(const string& a) { author = a; }
    void setYear(int y) { year = y; }
    void setCategory(const string& c) { category = c; }
    void setIsBorrowed(bool b) { isBorrowed = b; }
    void setBorrowedBy(const string& u) { borrowedBy = u; }
    void setLastActionTime(const string& t) { lastActionTime = t; }
   	void setTotalCopies(int count) { totalCopies = count; }
   	void setBorrowedCopies(int count) { borrowedCopies = count; }
    void setNext(Book* n) { next = n; }
};

class User : public LibraryEntity, public TimestampEntity 
{
private:
    string password;
    Role role;
    User* next;
public:
    User(string uname, string pwd, Role r) 
        : LibraryEntity(uname), password(pwd), role(r), next(nullptr) {}
    ~User() override {}
    void display() const override 
    {
        cout << "Username: " << id 
             << "\nPassword: " << password
             << "\nRole: " << (role == SUPERADMIN ? "Super Admin" : (role == ADMIN ? "Admin" : "User"))
             << "\nCreated: " << creationTime << endl;
    }
    friend void logUserAction(User& user, const string& action);
    string getPassword() const { return password; }
    Role getRole() const { return role; }
    User* getNext() const { return next; }
    void setPassword(const string& pwd) { password = pwd; }
    void setRole(Role r) { role = r; }
    void setNext(User* n) { next = n; }
};
class LibraryTransaction : public TimestampEntity 
{
private:
    string userId;
    string bookId;
    string actionType;
public:
    LibraryTransaction(string uid, string bid, string action)
        : userId(uid), bookId(bid), actionType(action) {}
    
    void display() const 
    {
        cout << "Transaction: " << actionType 
             << "\nUser: " << userId
             << "\nBook: " << bookId
             << "\nTime: " << creationTime << endl;
    }
    friend void validateTransaction(const LibraryTransaction& trans);
    string getUserId() const { return userId; }
    string getBookId() const { return bookId; }
    string getActionType() const { return actionType; }
};
void updateBookStatus(Book& book, bool status, const string& user) 
{
    book.isBorrowed = status;
    book.borrowedBy = status ? user : "";
}
void logBookAction(Book& book, const string& action) 
{
    cout << "Book Action Logged: " << action 
         << " for book " << book.getId() << endl;
}
void logUserAction(User& user, const string& action) 
{
    cout << "User Action Logged: " << action 
         << " by user " << user.getId() << endl;
}
void validateTransaction(const LibraryTransaction& trans)
{
    if (trans.userId.empty() || trans.bookId.empty()) 
    {
        cout << "Invalid transaction: missing user or book ID" << endl;
    } else {
        cout << "Transaction validated successfully" << endl;
    }
}
string getCurrentTime() 
{
    time_t now = time(0);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buffer);
}
void clearScreen() 
{
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}
string getPassword() 
{
    string password;
    char ch;
    while ((ch = _getch()) != '\r') 
    {
        if (ch == '\b') 
        {
            if (!password.empty()) 
            {
                cout << "\b \b";
                password.pop_back();
            }
        } else 
        {
            cout << '*';
            password += ch;
        }
    }
    cout << endl;
    return password;
}
size_t hashFunction(const string& key) 
{
    size_t hash = 0;
    for (char c : key) 
    {
        hash = (hash * 31) + c;
    }
    return hash % TABLE_SIZE;
}
template <typename T>
class Queue 
{
	private:
	    struct Node 
		{
	        T data;
	        Node* next;
	        Node(const T& value) : data(value), next(nullptr) {}
	    };
	    Node* front;
	    Node* rear;
	public:
	    Queue() : front(nullptr), rear(nullptr) {}
	    ~Queue() 
		{
	        clear();
	    }
	    void enqueue(const T& value) 
		{
	        Node* newNode = new Node(value);
	        if (rear == nullptr) 
			{
	            front = rear = newNode;
	        } else 
			{
	            rear->next = newNode;
	            rear = newNode;
	        }
	    }
	
	    bool dequeue(T& value) 
		{
	        if (isEmpty()) return false;
	        Node* temp = front;
	        value = front->data;
	        front = front->next;
	        if (front == nullptr) 
			{
	            rear = nullptr;
	        }
	        delete temp;
	        return true;
	    }
	    bool isEmpty() const 
		{
	        return front == nullptr;
	    }
	
	    void clear() 
		{
	        while (!isEmpty()) 
			{
	            T dummy;
	            dequeue(dummy);
	        }
	    }
};
class UserManager 
{
private:
    User* userTable[TABLE_SIZE];
    User* currentUser = nullptr;
    bool dataModified = false;
    void initializeTable() 
    {
        for (int i = 0; i < TABLE_SIZE; i++) 
        {
            userTable[i] = nullptr;
        }
    }
    void loadUsers() 
    {
        ifstream sfile(SUPERADMIN_FILE);
        if (sfile.is_open()) 
        {
            string line;
            while (getline(sfile, line)) 
            {
                try 
				{
                    size_t space_pos = line.find(' ');
                    if (space_pos != string::npos) 
                    {
                        string username = line.substr(0, space_pos);
                        string password = line.substr(space_pos + 1);
                        insertUser(username, password, SUPERADMIN, false);
                    }
                } catch (...) 
                {
                    continue;
                }
            }
            sfile.close();
        } else
        {
            ofstream createFile(SUPERADMIN_FILE);
            if (createFile.is_open()) 
            {
                createFile << "admin admin123\n";
                createFile.close();
            }
            insertUser("admin", "admin123", SUPERADMIN, false);
        }
        ifstream afile(ADMIN_FILE);
        if (afile.is_open()) 
        {
            string line;
            while (getline(afile, line)) 
            {
                try {
                    size_t space_pos = line.find(' ');
                    if (space_pos != string::npos) 
                    {
                        string username = line.substr(0, space_pos);
                        string password = line.substr(space_pos + 1);
                        insertUser(username, password, ADMIN, false);
                    }
                } catch (...) 
                {
                    continue;
                }
            }
            afile.close();
        }
        ifstream ufile(USER_FILE);
        if (ufile.is_open()) 
        {
            string line;
            while (getline(ufile, line)) 
            {
                try {
                    size_t space_pos = line.find(' ');
                    if (space_pos != string::npos) 
                    {
                        string username = line.substr(0, space_pos);
                        string password = line.substr(space_pos + 1);
                        insertUser(username, password, REGULAR_USER, false);
                    }
                } catch (...) 
                {
                    continue;
                }
            }
            ufile.close();
        }
    }
    void saveSuperAdmin() 
    {
        try 
		{
            ofstream file(SUPERADMIN_FILE);
            if (file.is_open()) 
            {
                for (int i = 0; i < TABLE_SIZE; i++)
                {
                    User* current = userTable[i];
                    while (current != nullptr) 
                    {
                        if (current->getRole() == SUPERADMIN) 
                        {
                            file << current->getId() << " " << current->getPassword() << "\n";
                        }
                        current = current->getNext();
                    }
                }
                file.close();
                dataModified = false;
            }
        } catch (const exception& e) 
        {
            cout << "Error saving super admin data: " << e.what() << endl;
        }
    }
    void saveAdmins() 
    {
        try 
		{
            ofstream file(ADMIN_FILE);
            if (file.is_open()) 
            {
                for (int i = 0; i < TABLE_SIZE; i++) 
                {
                    User* current = userTable[i];
                    while (current != nullptr) 
                    {
                        if (current->getRole() == ADMIN) 
                        {
                            file << current->getId() << " " << current->getPassword() << "\n";
                        }
                        current = current->getNext();
                    }
                }
                file.close();
                dataModified = false;
            }
        } catch (const exception& e) 
        {
            cerr << "Error saving admin data: " << e.what() << endl;
        }
    }
    void saveRegularUsers() 
    {
        try
		{
            ofstream file(USER_FILE);
            if (file.is_open()) 
            {
                for (int i = 0; i < TABLE_SIZE; i++) 
                {
                    User* current = userTable[i];
                    while (current != nullptr) 
                    {
                        if (current->getRole() == REGULAR_USER) 
                        {
                            file << current->getId() << " " << current->getPassword() << "\n";
                        }
                        current = current->getNext();
                    }
                }
                file.close();
                dataModified = false;
            }
        } catch (const exception& e)
        {
            cerr << "Error saving user data: " << e.what() << endl;
        }
    }
    bool isValidUsername(const string& username) 
    {
        return !username.empty() && username.length() <= 20;
    }

    bool isValidPassword(const string& password) 
    {
        return !password.empty() && password.length() >= 6;
    }
public:
    UserManager() 
    {
        initializeTable();
        loadUsers();
    }
    ~UserManager() 
    {
        if (dataModified) 
        {
            saveSuperAdmin();
            saveAdmins();
            saveRegularUsers();
        }
        for (int i = 0; i < TABLE_SIZE; i++) 
        {
            User* current = userTable[i];
            while (current != nullptr) 
            {
                User* temp = current;
                current = current->getNext();
                delete temp;
            }
        }
    }
    bool insertUser(const string& username, const string& password, Role role, bool saveImmediately = true) 
    {
        try 
        {
            if (!isValidUsername(username)) 
            {
                throw invalid_argument("Invalid username");
            }
            if (!isValidPassword(password)) 
            {
                throw invalid_argument("Invalid password");
            }

            size_t index = hashFunction(username);
            if (searchUser(username)) 
            {
                throw runtime_error("Username already exists");
            }
            User* newUser = new User(username, password, role);
            newUser->setNext(userTable[index]);
            userTable[index] = newUser;
            dataModified = true;
            logUserAction(*newUser, "User created");
            if (saveImmediately) 
            {
                if (role == ADMIN) saveAdmins();
                else if (role == REGULAR_USER) saveRegularUsers();
                else if (role == SUPERADMIN) saveSuperAdmin();
            }
            return true;
        } catch (const exception& e) 
        {
            cerr << "Error creating user: " << e.what() << endl;
            return false;
        }
    }
    User* searchUser(const string& username) 
    {
        size_t index = hashFunction(username);
        User* current = userTable[index];
        
        while (current != nullptr) 
        {
            if (current->getId() == username) 
            {
                return current;
            }
            current = current->getNext();
        }
        return nullptr;
    }
    User* login(const string& username, const string& password, Role role)
    {
        try 
        {
            User* user = searchUser(username);
            if (user && user->getPassword() == password && user->getRole() == role) 
            {
                currentUser = user;
                logUserAction(*user, "User logged in");
                return currentUser;
            }
            return nullptr;
        } catch (const exception& e) 
        {
            cerr << "Login error: " << e.what() << endl;
            return nullptr;
        }
    }
    void logout()
    {
        if (currentUser) 
        {
            logUserAction(*currentUser, "User logged out");
        }
        currentUser = nullptr;
    }
    bool isSuperAdmin() const 
    {
        return currentUser && currentUser->getRole() == SUPERADMIN;
    }
    bool isAdmin() const 
    {
        return currentUser && (currentUser->getRole() == ADMIN || currentUser->getRole() == SUPERADMIN);
    }
    bool registerAdmin(const string& username, const string& password)
    {
        if (!isSuperAdmin()) return false;
        if (searchUser(username)) return false;
        if (!isValidPassword(password)) return false;
        
        if (insertUser(username, password, ADMIN)) 
        {
            cout << "Admin registered successfully!" << endl;
            return true;
        }
        return false;
    }
    bool registerUser(const string& username, const string& password) 
    {
        if (searchUser(username)) return false;
        if (!isValidPassword(password)) return false;
        return insertUser(username, password, REGULAR_USER);
    }
    User* getCurrentUser() const 
    {
        return currentUser;
    }
    void displayAllAdmins() const 
    {
        User* admins[MAX_ADMINS];
        int adminCount = 0;
        
        for (int i = 0; i < TABLE_SIZE && adminCount < MAX_ADMINS; i++) 
        {
            User* current = userTable[i];
            while (current != nullptr && adminCount < MAX_ADMINS) 
            {
                if (current->getRole() == ADMIN) 
                {
                    admins[adminCount++] = current;
                }
                current = current->getNext();
            }
        }
        for (int i = 1; i < adminCount; i++) 
        {
            User* current = admins[i];
            int j = i;
            while (j > 0 && current->getId() < admins[j-1]->getId()) 
            {
                admins[j] = admins[j-1];
                j--;
            }
            admins[j] = current;
        }
        cout << "\n=== All Admin Accounts ===" << endl;
        if (adminCount == 0) 
        {
            cout << "No admin accounts found." << endl;
        } else 
        {
            for (int i = 0; i < adminCount; i++) 
            {
                admins[i]->display();
                cout << "----------------------------------" << endl;
            }
        }
    }
    void displayAllUsers() const 
    {
        User* users[MAX_USERS];  
        int userCount = 0;
        
        for (int i = 0; i < TABLE_SIZE && userCount < MAX_USERS; i++)
        {
            User* current = userTable[i];
            while (current != nullptr && userCount < MAX_USERS) 
            {
                if (current->getRole() == REGULAR_USER)
                {
                    users[userCount++] = current;
                }
                current = current->getNext();
            }
        }
        for (int i = 1; i < userCount; i++) 
        {
            User* current = users[i];
            int j = i;
            while (j > 0 && current->getId() < users[j-1]->getId()) 
            {
                users[j] = users[j-1];
                j--;
            }
            users[j] = current;
        }
        cout << "\n=== All User Accounts ===" << endl;
        if (userCount == 0) 
        {
            cout << "No user accounts found." << endl;
        } else {
            for (int i = 0; i < userCount; i++) 
            {
                users[i]->display();
                cout << "------------------------------------" << endl;
            }
        }
    }
    SystemStats getSystemStats() const
    {
        SystemStats stats = {0, 0, 0};
        
        for (int i = 0; i < TABLE_SIZE; i++) 
        {
            User* current = userTable[i];
            while (current != nullptr) 
            {
                if (current->getRole() == REGULAR_USER) stats.userCount++;
                else if (current->getRole() == ADMIN) stats.adminCount++;
                else if (current->getRole() == SUPERADMIN) stats.superAdminCount++;
                current = current->getNext();
            }
        }
        
        return stats;
    }
    bool changePassword(const string& username, const string& newPassword) 
    {
        User* user = searchUser(username);
        if (user && isValidPassword(newPassword)) 
        {
            user->setPassword(newPassword);
            dataModified = true;
            saveRegularUsers();
            return true;
        }
        return false;
    }
    
    void getAllUsers(User* users[], int& count) const {
        count = 0;
        for (int i = 0; i < TABLE_SIZE && count < MAX_USERS; i++) {
            User* current = userTable[i];
            while (current != nullptr && count < MAX_USERS) {
                if (current->getRole() == REGULAR_USER) {
                    users[count++] = current;
                }
                current = current->getNext();
            }
        }
    }
};
class BookManager
{
private:
    Book* bookTable[TABLE_SIZE];
    bool dataModified = false;
    Queue<string> reportQueue;
    void initializeTable()
    {
        for (int i = 0; i < TABLE_SIZE; i++)
        {
            bookTable[i] = nullptr;
        }
    }
    string trim(const string& str)
    {
        size_t first = str.find_first_not_of(" \t\n\r");
        if (string::npos == first) return str;
        size_t last = str.find_last_not_of(" \t\n\r");
        return str.substr(first, (last - first + 1));
    }
    void bubbleSort(Book* books[], int count) const
    {
        for (int i = 0; i < count-1; i++)
        {
            for (int j = 0; j < count-i-1; j++)
            {
                if (books[j]->getTitle() > books[j+1]->getTitle())
                {
                    Book* temp = books[j];
                    books[j] = books[j+1];
                    books[j+1] = temp;
                }
            }
        }
    }
    void loadBooks()
    {
        ifstream file(BOOK_FILE);
        if (!file.is_open())
        {
            cerr << "Error: Could not open book file!" << endl;
            return;
        }
        string line;
        while (getline(file, line))
        {
            try
            {
                if (line.empty()) continue;

                size_t pos1 = line.find('|');
                size_t pos2 = line.find('|', pos1 + 1);
                size_t pos3 = line.find('|', pos2 + 1);
                size_t pos4 = line.find('|', pos3 + 1);
                size_t pos5 = line.find('|', pos4 + 1);
                size_t pos6 = line.find('|', pos5 + 1);
                size_t pos7 = line.find('|', pos6 + 1);
                size_t pos8 = line.find('|', pos7 + 1);
                if (pos6 == string::npos)
                {
                    cerr << "Skipping invalid line (missing fields): " << line << endl;
                    continue;
                }
                string isbn = trim(line.substr(0, pos1));
                string title = trim(line.substr(pos1 + 1, pos2 - pos1 - 1));
                string author = trim(line.substr(pos2 + 1, pos3 - pos2 - 1));
                int year = stoi(trim(line.substr(pos3 + 1, pos4 - pos3 - 1)));
                string category = trim(line.substr(pos4 + 1, pos5 - pos4 - 1));
                int totalCopies = stoi(trim(line.substr(pos5 + 1, pos6 - pos5 - 1)));
                int borrowedCopies = stoi(trim(line.substr(pos6 + 1, pos7 - pos6 - 1)));
                string lastActionTime = (pos8 != string::npos) ? trim(line.substr(pos8 + 1)) : "";
                size_t index = hashFunction(isbn);
                Book* newBook = new Book(isbn, title, author, year, category, totalCopies);
                newBook->setBorrowedCopies(borrowedCopies);
                newBook->setLastActionTime(lastActionTime);
                newBook->setNext(bookTable[index]);
                bookTable[index] = newBook;
            } 
            catch (const exception& e)
            {
                cerr << "Error parsing line: " << line << " (" << e.what() << ")" << endl;
            }
        }
        file.close();
    }
    void insertionSortByTitle(Book* books[], int count) const
    {
        for (int i = 1; i < count; i++)
        {
            Book* current = books[i];
            int j = i;
            while (j > 0 && current->getTitle() < books[j-1]->getTitle())
            {
                books[j] = books[j-1];
                j--;
            }
            books[j] = current;
        }
    }
    void mergeSort(Book* books[], int left, int right, bool byTitle = true) const
    {
        if (left < right)
        {
            int mid = left + (right - left) / 2;
            mergeSort(books, left, mid, byTitle);
            mergeSort(books, mid + 1, right, byTitle);
            int n1 = mid - left + 1;
            int n2 = right - mid;
            Book** L = new Book*[n1];
            Book** R = new Book*[n2];
            for (int i = 0; i < n1; i++)
                L[i] = books[left + i];
            for (int j = 0; j < n2; j++)
                R[j] = books[mid + 1 + j];
            int i = 0, j = 0, k = left;
            while (i < n1 && j < n2)
            {
                bool condition = byTitle ?
                    (L[i]->getTitle() <= R[j]->getTitle()) :
                    (L[i]->getYear() <= R[j]->getYear());
                if (condition)
                {
                    books[k] = L[i];
                    i++;
                } else
                {
                    books[k] = R[j];
                    j++;
                }
                k++;
            }
            while (i < n1)
            {
                books[k] = L[i];
                i++;
                k++;
            }
            while (j < n2)
            {
                books[k] = R[j];
                j++;
                k++;
            }
            delete[] L;
            delete[] R;
        }
    }
    Book* binarySearch(Book* books[], int left, int right, const string& title)
    {
        while (left <= right)
        {
            int mid = left + (right - left) / 2;

            if (books[mid]->getTitle() == title)
                return books[mid];

            if (books[mid]->getTitle() < title)
                left = mid + 1;
            else
                right = mid - 1;
        }
        return nullptr;
    }
    void saveBooks() 
	{
	    try {
	        ofstream file(BOOK_FILE);
	        if (file.is_open()) 
			{
	            for (int i = 0; i < TABLE_SIZE; i++) 
				{
	                Book* current = bookTable[i];
	                while (current != nullptr) 
					{
	                    string line = current->getId() + "|" + current->getTitle() + "|"
	                               + current->getAuthor() + "|" + to_string(current->getYear()) + "|"
	                               + current->getCategory() + "|" + to_string(current->getTotalCopies()) + "|"
	                               + to_string(current->getBorrowedCopies()) + "|"
	                               + current->getLastActionTime();
	                    file << line << endl;
	                    current = current->getNext();
	                }
	            }
	            file.close();
	            dataModified = false;
	        }
	    } catch (const exception& e) 
		{
	        cerr << "Error saving books: " << e.what() << endl;
	    }
	}
    bool isValidISBN(const string& isbn)
    {
        return !isbn.empty() && isbn.length() <= 20;
    }
public:
    BookManager()
	{
        initializeTable();
        loadBooks();
    }
    ~BookManager() 
	{
        if (dataModified)
		{
            saveBooks();
        }
        for (int i = 0; i < TABLE_SIZE; i++) 
		{
            Book* current = bookTable[i];
            while (current != nullptr) 
			{
                Book* temp = current;
                current = current->getNext();
                delete temp;
            }
        }
    }
	void checkAllUsersOverdueAndFines(int maxBorrowDays, double finePerDay, UserManager& userManager) {
	    try {
	        auto now = chrono::system_clock::now();
	        time_t currentTime = chrono::system_clock::to_time_t(now);
	        bool hasOverdue = false;
	        double grandTotalFine = 0.0;
	        struct UserFine {
	            string username;
	            double fine;
	            bool isUsed;
	        };
	        UserFine userFines[MAX_USERS];
	        int fineCount = 0;
	        for (int i = 0; i < MAX_USERS; i++) {
	            userFines[i].isUsed = false;
	        }
	
	        ofstream outFile(OVERDUE_REPORT_FILE, ios::app);
	        if (!outFile.is_open()) {
	            throw runtime_error("Failed to open overdue report file");
	        }
	        cout << "\n=== Overdue Fines Summary ===\n";
	        cout << "Generated at: " << getCurrentTime() << "\n\n";
	        outFile << "\n=== Overdue Fines Summary ===\n";
	        outFile << "Generated at: " << getCurrentTime() << "\n\n";
	        User* users[MAX_USERS];
	        int userCount = 0;
	        userManager.getAllUsers(users, userCount);
	        for (int i = 0; i < userCount; i++) {
	            string username = users[i]->getId();
	            BorrowRecord borrowRecords[MAX_BORROW_RECORDS];
	            int recordCount = 0;
	            ifstream borrowFile(BORROW_FILE);
	            if (!borrowFile.is_open()) {
	                throw runtime_error("Failed to open borrow.txt");
	            }
	            string line;
	            while (getline(borrowFile, line)) {
	                if (line.find("User: " + username + " | Borrow Book: ") != string::npos) {
	                    size_t isbnPos = line.find("Borrow Book: ") + 13;
	                    size_t timePos = line.find(" | Time: ") + 8;
	                    string isbn = line.substr(isbnPos, line.find(" |", isbnPos) - isbnPos);
	                    string borrowTimeStr = line.substr(timePos);
	                    Book* book = searchBook(isbn);
	                    string title = book ? book->getTitle() : "Unknown Title";
	                    if (recordCount < MAX_BORROW_RECORDS) {
	                        borrowRecords[recordCount] = {isbn, borrowTimeStr, title};
	                        recordCount++;
	                    }
	                }
	            }
	            borrowFile.close();
	            ifstream returnFile(RETURN_FILE);
	            if (returnFile.is_open()) {
	                while (getline(returnFile, line)) {
	                    if (line.find("User: " + username + " | Return Book: ") != string::npos) {
	                        size_t isbnPos = line.find("Return Book: ") + 13;
	                        string isbn = line.substr(isbnPos, line.find(" |", isbnPos) - isbnPos);
	                        for (int j = 0; j < recordCount; j++) {
	                            if (borrowRecords[j].isbn == isbn) {
	                                for (int k = j; k < recordCount - 1; k++) {
	                                    borrowRecords[k] = borrowRecords[k + 1];
	                                }
	                                recordCount--;
	                                break;
	                            }
	                        }
	                    }
	                }
	                returnFile.close();
	            }
	            if (recordCount > 0) {
	                double totalFine = 0.0;
	                bool userHasOverdue = false;
	                struct OverdueDetail {
	                    string isbn;
	                    string title;
	                    string borrowTimeStr;
	                    int overdueDays;
	                    double fine;
	                };
	                OverdueDetail overdueDetails[MAX_BORROW_RECORDS];
	                int detailCount = 0;
	                for (int j = 0; j < recordCount; j++) {
	                    string isbn = borrowRecords[j].isbn;
	                    string borrowTimeStr = borrowRecords[j].borrowTimeStr;
	                    string title = borrowRecords[j].title;
	                    tm borrowTm = {};
	                    istringstream ss(borrowTimeStr);
	                    ss >> get_time(&borrowTm, "%Y-%m-%d %H:%M:%S");
	                    if (ss.fail()) {
	                        throw runtime_error("Invalid borrow time format for ISBN " + isbn);
	                    }
	                    time_t borrowTime = mktime(&borrowTm);
	                    double secondsDiff = difftime(currentTime, borrowTime);
	                    int daysDiff = static_cast<int>(secondsDiff / (60 * 60 * 24));
	
	                    if (daysDiff > maxBorrowDays) {
	                        hasOverdue = true;
	                        userHasOverdue = true;
	                        int overdueDays = daysDiff - maxBorrowDays;
	                        double fine = overdueDays * finePerDay;
	                        totalFine += fine;
	                        if (detailCount < MAX_BORROW_RECORDS) {
	                            overdueDetails[detailCount] = {isbn, title, borrowTimeStr, overdueDays, fine};
	                            detailCount++;
	                        }
	                    }
	                }
	                if (userHasOverdue) {
	                    cout << "User: " << username << "\n";
	                    cout << left << setw(15) << "ISBN" << setw(25) << "Title"
	                         << setw(22) << "Borrow Time" << setw(18) << "Overdue Days"
	                         << setw(10) << "Fine (RM)" << "\n";
	                    cout << setfill('-') << setw(90) << "-" << setfill(' ') << "\n";
	                    outFile << "User: " << username << "\n";
	                    outFile << left << setw(15) << "ISBN" << setw(25) << "Title"
	                            << setw(22) << "Borrow Time" << setw(18) << "Overdue Days"
	                            << setw(10) << "Fine (RM)" << "\n";
	                    outFile << setfill('-') << setw(90) << "-" << setfill(' ') << "\n";
	
	                    for (int j = 0; j < detailCount; j++) {
	                        cout << left << setw(15) << overdueDetails[j].isbn
	                             << setw(25) << overdueDetails[j].title
	                             << setw(22) << overdueDetails[j].borrowTimeStr
	                             << setw(18) << overdueDetails[j].overdueDays
	                             << setw(10) << fixed << setprecision(2) << overdueDetails[j].fine << "\n";
	                        outFile << left << setw(15) << overdueDetails[j].isbn
	                                << setw(25) << overdueDetails[j].title
	                                << setw(22) << overdueDetails[j].borrowTimeStr
	                                << setw(18) << overdueDetails[j].overdueDays
	                                << setw(10) << fixed << setprecision(2) << overdueDetails[j].fine << "\n";
	                    }
	                    cout << "\nTotal Fine: RM " << fixed << setprecision(2) << totalFine << "\n\n";
	                    outFile << "\nTotal Fine: RM " << fixed << setprecision(2) << totalFine << "\n\n";
	                    int existingIndex = -1;
	                    for (int k = 0; k < fineCount; k++) {
	                        if (userFines[k].username == username && userFines[k].isUsed) {
	                            existingIndex = k;
	                            break;
	                        }
	                    }
	                    if (existingIndex != -1) {
	                        userFines[existingIndex].fine += totalFine;
	                    } else if (fineCount < MAX_USERS) {
	                        userFines[fineCount] = {username, totalFine, true};
	                        fineCount++;
	                    }
	                    grandTotalFine += totalFine;
	                }
	            }
	        }
	        if (!hasOverdue) {
	            cout << "No overdue books found for any user.\n";
	            outFile << "No overdue books found for any user.\n";
	        }
	        if (hasOverdue) {
	            cout << "\n=== Summary of Fines ===\n";
	            cout << left << setw(20) << "Username" << right << setw(15) << "Total Fine (RM)" << left << "\n";
	            cout << setfill('-') << setw(35) << "-" << setfill(' ') << "\n";
	            outFile << "\n=== Summary of Fines ===\n";
	            outFile << left << setw(20) << "Username" << right << setw(15) << "Total Fine (RM)" << left << "\n";
	            outFile << setfill('-') << setw(35) << "-" << setfill(' ') << "\n";
	            for (int i = 0; i < fineCount; i++) {
	                if (userFines[i].isUsed) {
	                    cout << left << setw(20) << userFines[i].username
	                         << right << setw(15) << fixed << setprecision(2) << userFines[i].fine << left << "\n";
	                    outFile << left << setw(20) << userFines[i].username
	                            << right << setw(15) << fixed << setprecision(2) << userFines[i].fine << left << "\n";
	                }
	            }
	            cout << "\nGrand Total Fine: RM " << fixed << setprecision(2) << grandTotalFine << "\n";
	            outFile << "\nGrand Total Fine: RM " << fixed << setprecision(2) << grandTotalFine << "\n";
	        }
	        outFile.close();
	        cout << "Overdue report saved to " << OVERDUE_REPORT_FILE << "\n";
	    } catch (const exception& e) {
	        cout << "Error checking overdue books and fines: " << e.what() << "\n";
	    }
	}
    ReportData generateReportData()
    {
        ReportData data;
        data.totalBooks = 0;
        data.availableBooks = 0;
        data.borrowedBooks = 0;
        data.generationTime = getCurrentTime();
        for (int i = 0; i < TABLE_SIZE; i++)
        {
            Book* current = bookTable[i];
            while (current != nullptr)
            {
                data.totalBooks += current->getTotalCopies();
                data.borrowedBooks += current->getBorrowedCopies();
                data.availableBooks += (current->getTotalCopies() - current->getBorrowedCopies());
                current = current->getNext();
            }
        }
        return data;
    }
    bool editBook(const string& isbn) 
	{
        size_t index = hashFunction(isbn);
        Book* current = bookTable[index];
        while (current != nullptr) 
		{
            if (current->getId() == isbn) 
			{
                cout << "Editing book: " << current->getTitle() << endl;
                cout << "New Title (No change write previous): ";
                string newTitle;
                getline(cin, newTitle);
                if (!newTitle.empty()) current->setTitle(newTitle);
                cout << "New Author (No change write previous): ";
                string newAuthor;
                getline(cin, newAuthor);
                if (!newAuthor.empty()) current->setAuthor(newAuthor);
                cout << "New Year (0 to keep current): ";
                int newYear;
                cin >> newYear;
                cin.ignore();
                if (newYear != 0) current->setYear(newYear);
                cout << "New Category (No change write previous): ";
                string newCategory;
                getline(cin, newCategory);
                if (!newCategory.empty()) current->setCategory(newCategory);
                dataModified = true;
                saveBooks();
                cout << "Book updated successfully!\n";
                return true;
            }
            current = current->getNext();
        }
        cout << "Book not found.\n";
        return false;
    }
    bool deleteBook(const string& isbn) 
	{
        size_t index = hashFunction(isbn);
        Book* current = bookTable[index];
        Book* prev = nullptr;
        while (current != nullptr) 
		{
            if (current->getId() == isbn) 
			{
                if (prev == nullptr) 
				{
                    bookTable[index] = current->getNext();
                } else 
				{
                    prev->setNext(current->getNext());
                }

                delete current;
                dataModified = true;
                saveBooks();
                cout << "Book deleted successfully!\n";
                return true;
            }
            prev = current;
            current = current->getNext();
        }
        cout << "Book not found.\n";
        return false;
    }
    bool insertBook(const string& isbn, const string& title, const string& author,
                    int year, const string& category, int totalCopies = 1, bool saveImmediately = true) 
					{
        try 
		{
            if (!isValidISBN(isbn)) throw invalid_argument("Invalid ISBN");
            size_t index = hashFunction(isbn);
            Book* newBook = new Book(isbn, title, author, year, category, totalCopies);
            newBook->setNext(bookTable[index]);
            bookTable[index] = newBook;
            dataModified = true;
            logBookAction(*newBook, "Book added to system");
            if (saveImmediately) saveBooks();
            return true;
        } catch (const exception& e) 
		{
            cerr << "Error adding book: " << e.what() << endl;
            return false;
        }
    }
    Book* searchBook(const string& isbn) 
	{
        size_t index = hashFunction(isbn);
        Book* current = bookTable[index];
        while (current != nullptr) 
		{
            if (current->getId() == isbn) 
			{
                return current;
            }
            current = current->getNext();
        }
        return nullptr;
    }
    void listBooks() const 
	{
        Book* books[MAX_BOOKS];
        int bookCount = 0;
        for (int i = 0; i < TABLE_SIZE && bookCount < MAX_BOOKS; i++) 
		{
            Book* current = bookTable[i];
            while (current != nullptr && bookCount < MAX_BOOKS) 
			{
                books[bookCount++] = current;
                current = current->getNext();
            }
        }
        insertionSortByTitle(books, bookCount);
        cout << "\n****************************************************" << endl;
        cout << "\n**Book List (Sorted by Title - Insertion Sort) ****" << endl;
        cout << "\n****************************************************" << endl;
        cout << left << setw(15) << "ISBN" << setw(45) << "Title" << setw(25) << "Author" 
             << setw(10) << "Year" << setw(15) << "Category" << setw(10) << "Total" 
             << setw(10) << "Avail" << "Status" << endl;
        cout << setfill('-') << setw(140) << "-" << setfill(' ') << endl;
        for (int i = 0; i < bookCount; i++) {
            string displayTitle = (books[i]->getTitle().length() > 50) ? 
                books[i]->getTitle().substr(0, 27) + "..." : books[i]->getTitle();
            cout << setw(15) << books[i]->getId() 
                 << setw(45) << displayTitle 
                 << setw(25) << books[i]->getAuthor() 
                 << setw(10) << books[i]->getYear() 
                 << setw(15) << books[i]->getCategory() 
                 << setw(10) << books[i]->getTotalCopies()
                 << setw(10) << (books[i]->getTotalCopies() - books[i]->getBorrowedCopies())
                 << (books[i]->getBorrowedCopies() > 0 ? 
                    (to_string(books[i]->getBorrowedCopies()) + " borrowed") : "All available") 
                 << endl;
        }
    }
    bool borrowBook(const string& isbn, const string& username) 
	{
	    try 
		{
	        Book* book = searchBook(isbn);
	        if (!book) 
			{
	            throw runtime_error("Book not found");
	        }
	        if (book->getTotalCopies() <= book->getBorrowedCopies()) 
			{
	            throw runtime_error("All copies of this book have been borrowed");
	        }
	        book->setBorrowedCopies(book->getBorrowedCopies() + 1);
	        dataModified = true;
	        saveBooks();
	        LibraryTransaction trans(username, isbn, "BORROW");
	        validateTransaction(trans);
	        ofstream outFile(BORROW_FILE, ios::app);
	        if (outFile.is_open()) 
			{
	            outFile << "User: " << username << " | Borrow Book: " << isbn 
	                    << " | Time: " << getCurrentTime() << endl;
	            outFile.close();
	        }
	        cout << "Book borrowed successfully by " << username << "!" << endl;
	        return true;
	    } catch (const exception& e) 
		{
	        cerr << "Error borrowing book: " << e.what() << endl;
	        return false;
	    }
	}
    bool returnBook(const string& isbn, const string& username) 
	{
	    try
	    {
	        Book* book = searchBook(isbn);
	        if (!book) 
	        {
	            throw runtime_error("Book not found");
	        }
	        if (book->getBorrowedCopies() <= 0) 
	        {
	            throw runtime_error("No copies of this book are currently borrowed");
	        }
	        book->setBorrowedCopies(book->getBorrowedCopies() - 1);
	        dataModified = true;
	        saveBooks();
	
	        ofstream outFile(RETURN_FILE, ios::app);
	        if (outFile.is_open()) 
	        {
	            outFile << "User: " << username << " | Return Book: " << isbn << " | Time: " << getCurrentTime() << endl;
	            outFile.close();
	        }
	        cout << "Book returned successfully by " << username << "!" << endl;
	        return true;
	    } 
	    catch (const exception& e) 
	    {
	        cerr << "Error returning book: " << e.what() << endl;
	        return false;
	    }
	}
    bool addBookCopies(const string& isbn, int additionalCopies) 
	{
	    if (additionalCopies <= 0) 
		{
	        cout << "Number of copies to add must be positive." << endl;
	        return false;
	    }
	    Book* book = searchBook(isbn);
	    if (!book) 
		{
	        cout << "Book with ISBN " << isbn << " not found." << endl;
	        return false;
	    }
	    int newTotal = book->getTotalCopies() + additionalCopies;
	    if (newTotal > MAX_COPIES) 
		{
	        cout << "Cannot add " << additionalCopies << " copies. Maximum is " 
	             << MAX_COPIES << " (currently have " << book->getTotalCopies() << ")" << endl;
	        return false;
	    }
	    book->setTotalCopies(newTotal);
	    dataModified = true;
	    saveBooks();
	    cout << "Successfully added " << additionalCopies << " copies. New total: " 
	         << newTotal << endl;
	    return true;
	}
    bool removeBookCopies(const string& isbn, int copiesToRemove) 
	{
	    if (copiesToRemove <= 0) 
		{
	        cout << "Number of copies to remove must be positive." << endl;
	        return false;
	    }
	    Book* book = searchBook(isbn);
	    if (!book) 
		{
	        cout << "Book with ISBN " << isbn << " not found." << endl;
	        return false;
	    }
	    int currentAvailable = book->getTotalCopies() - book->getBorrowedCopies();
	    if (copiesToRemove > currentAvailable) 
		{
	        cout << "Cannot remove " << copiesToRemove << " copies. Only " 
	             << currentAvailable << " are available (total: " << book->getTotalCopies() 
	             << ", borrowed: " << book->getBorrowedCopies() << ")" << endl;
	        return false;
	    }
	    int newTotal = book->getTotalCopies() - copiesToRemove;
	    if (newTotal <= 0) 
		{
	        cout << "Cannot remove all copies. Use deleteBook instead." << endl;
	        return false;
	    }
	    book->setTotalCopies(newTotal);
	    dataModified = true;
	    saveBooks();
	    cout << "Successfully removed " << copiesToRemove << " copies. New total: " 
	         << newTotal << endl;
	    return true;
	}
    int getAvailableCopies(const string& isbn) 
    {
        Book* book = searchBook(isbn);
        if (!book) return 0;
        return book->getTotalCopies() - book->getBorrowedCopies();
    }
    int getTotalCopies(const string& isbn) 
    {
        Book* book = searchBook(isbn);
        if (!book) return 0;
        return book->getTotalCopies();
    }
    int getBorrowedCopies(const string& isbn) 
    {
        Book* book = searchBook(isbn);
        if (!book) return 0;
        return book->getBorrowedCopies();
    }
    void displayAllUserHistory() 
	{
        ifstream file(BORROW_FILE);
        if (file.is_open()) 
		{
            string line;
            cout << "=== All User Borrow History ===" << endl;
            while (getline(file, line)) 
			{
                cout << line << endl;
            }
            file.close();
        } else {
            cout << "No borrow history found." << endl;
        }
        
        ifstream returnFile(RETURN_FILE);
	    if (returnFile.is_open()) 
		{
	        string line;
	        cout << "\n=== All User Return History ===" << endl;
	        while (getline(returnFile, line)) 
			{
	            cout << line << endl;
	        }
	        returnFile.close();
	    } else 
		{
	        cout << "No return history found." << endl;
		}
    }
    void getCategoryStats(CategoryStats stats[], int& count) {
	    count = 0;
	    for (int i = 0; i < TABLE_SIZE; i++) {
	        Book* current = bookTable[i];
	        while (current != nullptr) {
	            string category = current->getCategory();
	            int index = -1;
	            for (int j = 0; j < count; j++) {
	                if (stats[j].category == category) {
	                    index = j;
	                    break;
	                }
	            }
	            if (index == -1 && count < MAX_CATEGORIES) {
	                index = count++;
	                stats[index].category = category;
	                stats[index].bookCount = 0;
	                stats[index].availableCount = 0;
	            }
	            if (index != -1) {
	                stats[index].bookCount += current->getTotalCopies();
	                stats[index].availableCount += (current->getTotalCopies() - current->getBorrowedCopies());
	            }
	            current = current->getNext();
	        }
	    }
	}
	void getPopularBooks(PopularBook popularBooks[], int& count) {
	    count = 0;
	    for (int i = 0; i < TABLE_SIZE; i++) {
	        Book* current = bookTable[i];
	        while (current != nullptr) {
	            string isbn = current->getId();
	            int index = -1;
	            for (int j = 0; j < count; j++) {
	                if (popularBooks[j].isbn == isbn) {
	                    index = j;
	                    break;
	                }
	            }
	            if (index == -1 && count < MAX_POPULAR_BOOKS) {
	                index = count++;
	                popularBooks[index].isbn = isbn;
	                popularBooks[index].title = current->getTitle();
	                popularBooks[index].borrowCount = 0;
	            }
	            current = current->getNext();
	        }
	    }
	    ifstream borrowFile(BORROW_FILE);
	    if (borrowFile.is_open()) {
	        string line;
	        while (getline(borrowFile, line)) {
	            size_t pos = line.find("Borrow Book: ");
	            if (pos != string::npos) {
	                string isbn = line.substr(pos + 13, line.find(" |") - (pos + 13));
	                for (int j = 0; j < count; j++) {
	                    if (popularBooks[j].isbn == isbn) {
	                        popularBooks[j].borrowCount++;
	                        break;
	                    }
	                }
	            }
	        }
	        borrowFile.close();
	    }
	    for (int i = 0; i < count-1; i++) {
	        for (int j = 0; j < count-i-1; j++) {
	            if (popularBooks[j].borrowCount < popularBooks[j+1].borrowCount) {
	                swap(popularBooks[j], popularBooks[j+1]);
	            }
	        }
	    }
	}
    void displaySortedBooks(bool byTitle) 
	{
        Book* books[MAX_BOOKS];
        int bookCount = 0;
        for (int i = 0; i < TABLE_SIZE && bookCount < MAX_BOOKS; i++) 
		{
            Book* current = bookTable[i];
            while (current != nullptr && bookCount < MAX_BOOKS) 
			{
                books[bookCount++] = current;
                current = current->getNext();
            }
        }
        if (byTitle) 
		{
            insertionSortByTitle(books, bookCount);
        } else 
		{
            mergeSort(books, 0, bookCount - 1, false);
        }
        cout << "\n=== Sorted Books ===" << endl;
        cout << left << setw(15) << "ISBN" << setw(30) << "Title" 
             << setw(20) << "Author" << setw(10) << "Year" << endl;
        for (int i = 0; i < bookCount; i++) 
		{
            cout << setw(15) << books[i]->getId() 
                 << setw(30) << books[i]->getTitle() 
                 << setw(20) << books[i]->getAuthor() 
                 << setw(10) << books[i]->getYear() << endl;
        }
    }
    Book* searchBookByTitle(const string& title) 
	{
        Book* books[MAX_BOOKS];
        int bookCount = 0;
        for (int i = 0; i < TABLE_SIZE && bookCount < MAX_BOOKS; i++) 
		{
            Book* current = bookTable[i];
            while (current != nullptr && bookCount < MAX_BOOKS) 
			{
                books[bookCount++] = current;
                current = current->getNext();
            }
        }
        insertionSortByTitle(books, bookCount);
        Book* found = binarySearch(books, 0, bookCount - 1, title);
        if (found) 
		{
            cout << "Book found:" << endl;
            found->display();
        } else 
		{
            cout << "Book not found!" << endl;
        }
        return found;
    }
    void generateSummaryReport() 
	{
        ReportData data = generateReportData();
        ofstream file(SUMMARY_REPORT_FILE);
        if (file.is_open()) 
		{
            file << "=== Library Summary Report ===" << endl;
            file << "Generated at: " << data.generationTime << endl;
            file << "Total Books: " << data.totalBooks << endl;
            file << "Available Books: " << data.availableBooks << endl;
            file << "Borrowed Books: " << data.borrowedBooks << endl;
            file.close();
            cout << "Summary report generated successfully!" << endl;
        } else 
		{
            cout << "Failed to generate report!" << endl;
        }
    }
    void generateUserSummaryReport(const string& username) {
	    try {
	        const string reportFilename = "user_summary_report.txt";
	        ofstream outFile(reportFilename, ios::app);
	        if (!outFile.is_open()) {
	            throw runtime_error("Failed to create report file");
	        }
	
	        time_t now = time(nullptr);
	        char currentTimeStr[80];
	        strftime(currentTimeStr, sizeof(currentTimeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));
	        string currentTime = currentTimeStr;
	
	        int totalBorrowed = 0;
	        int returnedCount = 0;
	        int notReturnedCount = 0;
	
	        const int MAX_RECORDS = 1000;
	        string rentalRecords[MAX_RECORDS];
	        int recordCount = 0;
	
	        ifstream borrowFile(BORROW_FILE);
	        if (borrowFile.is_open()) {
	            string line;
	            while (getline(borrowFile, line) && recordCount < MAX_RECORDS) {
	                if (line.find("User: " + username + " | Borrow Book: ") != string::npos) {
	                    totalBorrowed++;
	
	                    size_t isbnPos = line.find("Borrow Book: ") + 13;
	                    size_t timePos = line.find(" | Time: ") + 9;
	                    string isbn = line.substr(isbnPos, line.find(" |", isbnPos) - isbnPos);
	                    string borrowTime = line.substr(timePos);
	
	                    Book* book = searchBook(isbn);
	                    string title = book ? book->getTitle() : "Book not found";
	
	                    bool isReturned = false;
	                    ifstream returnFile(RETURN_FILE);
	                    if (returnFile.is_open()) {
	                        string returnLine;
	                        while (getline(returnFile, returnLine)) {
	                            if (returnLine.find("User: " + username + " | Return Book: " + isbn) != string::npos) {
	                                isReturned = true;
	                                break;
	                            }
	                        }
	                        returnFile.close();
	                    }
	
	                    if (!isReturned) {
	                        notReturnedCount++;
	                    } else {
	                        returnedCount++;
	                    }
	
	                    char record[256];
	                    snprintf(record, sizeof(record),
	                             "%s | Borrowed: %s | Returned: %s",
	                             title.c_str(),
	                             borrowTime.c_str(),
	                             isReturned ? "Yes" : "No");
	
	                    rentalRecords[recordCount++] = record;
	                }
	            }
	            borrowFile.close();
	        }
	
	        outFile << "\n=== USER SUMMARY REPORT === " << currentTime << "\n";
	        outFile << "User: " << username << "\n";
	        outFile << "Total Books Borrowed: " << totalBorrowed << "\n";
	        outFile << "Books Returned: " << returnedCount << "\n";
	        outFile << "Books Not Returned: " << notReturnedCount << "\n\n";
	
	        outFile << "Rental Records:\n";
	        for (int i = 0; i < recordCount; ++i) {
	            outFile << i + 1 << ". " << rentalRecords[i] << "\n";
	        }
	
	        cout << "\n=== USER SUMMARY REPORT ===\n";
	        cout << "User: " << username << "\n";
	        cout << "Total Books Borrowed: " << totalBorrowed << "\n";
	        cout << "Books Returned: " << returnedCount << "\n";
	        cout << "Books Not Returned: " << notReturnedCount << "\n\n";
	
	        cout << "Rental Records:\n";
	        for (int i = 0; i < recordCount; ++i) {
	            cout << i + 1 << ". " << rentalRecords[i] << "\n";
	        }
	
	        cout << "\nReport saved to " << reportFilename << endl;
	
	    } catch (const exception& e) {
	        cerr << "Error generating user summary report: " << e.what() << endl;
	    }
	}

    void displayUserHistory(const string& username) 
	{
	    ifstream borrowFile(BORROW_FILE);
	    if (borrowFile.is_open()) 
	    {
	        string line;
	        cout << "\n=== Borrow History for " << username << " ===" << endl;
	        while (getline(borrowFile, line)) 
	        {
	            if (line.find("User: " + username + " | Borrow Book: ") != string::npos) 
	            {
	                cout << line << endl;
	            }
	        }
	        borrowFile.close();
	    } 
	    else 
	    {
	        cout << "No borrow history found for this user." << endl;
	    }
	    ifstream returnFile(RETURN_FILE);
	    if (returnFile.is_open()) 
	    {
	        string line;
	        cout << "\n=== Return History for " << username << " ===" << endl;
	        while (getline(returnFile, line)) 
	        {
	            size_t pos = 0;
	            while ((pos = line.find("User: ", pos)) != string::npos) 
	            {
	                size_t endPos = line.find("User: ", pos + 1);
	                string record = (endPos == string::npos) ? line.substr(pos) : line.substr(pos, endPos - pos);
	
	                if (record.find("User: " + username + " | Return Book: ") != string::npos) 
	                {
	                    cout << record << endl;
	                }
	                pos = endPos;
	            }
	        }
	        returnFile.close();
	    } 
	    else 
	    {
	        cout << "No return history found for this user." << endl;
	    }
	}
	void checkOverdueAndFines(const string& username, int maxBorrowDays, double finePerDay)
	{
		try 
	    {
	        auto now = chrono::system_clock::now();
	        time_t currentTime = chrono::system_clock::to_time_t(now);
	        ifstream borrowFile(BORROW_FILE);
	        if (!borrowFile.is_open()) 
	        {
	            throw runtime_error("Failed to open borrow.txt");
	        }
	        BorrowRecord borrowRecords[MAX_BORROW_RECORDS];
	        int recordCount = 0;
	        string line;
	        while (getline(borrowFile, line)) 
	        {
	            if (line.find("User: " + username + " | Borrow Book: ") != string::npos) 
	            {
	                size_t isbnPos = line.find("Borrow Book: ") + 13;
	                size_t timePos = line.find(" | Time: ") + 8;
	                string isbn = line.substr(isbnPos, line.find(" |", isbnPos) - isbnPos);
	                string borrowTimeStr = line.substr(timePos);
	                Book* book = searchBook(isbn);
	                string title = book ? book->getTitle() : "Unknown Title";
	
	                if (recordCount < MAX_BORROW_RECORDS) {
	                    borrowRecords[recordCount] = {isbn, borrowTimeStr, title};
	                    recordCount++;
	                }
	            }
	        }
	        borrowFile.close();
	        ifstream returnFile(RETURN_FILE);
	        if (returnFile.is_open()) 
	        {
	            while (getline(returnFile, line)) 
	            {
	                if (line.find("User: " + username + " | Return Book: ") != string::npos) 
	                {
	                    size_t isbnPos = line.find("Return Book: ") + 13;
	                    string isbn = line.substr(isbnPos, line.find(" |", isbnPos) - isbnPos);
	                    // 移除第一条匹配的借阅记录
	                    for (int j = 0; j < recordCount; j++) {
	                        if (borrowRecords[j].isbn == isbn) {
	                            for (int k = j; k < recordCount - 1; k++) {
	                                borrowRecords[k] = borrowRecords[k + 1];
	                            }
	                            recordCount--;
	                            break;
	                        }
	                    }
	                }
	            }
	            returnFile.close();
	        }	
	        bool hasOverdue = false;
	        double totalFine = 0.0;
	        cout << "=== Overdue Books and Fines for " << username << " ===" << endl;
	        cout << left 
	             << setw(15) << "ISBN" << setw(25) << "Title"
	             << setw(20) << "Borrow Time" << right << setw(18) << "Overdue Days"
	             << setw(18) << "Fine (RM)" << left << endl;
	        cout << setfill('-') << setw(96) << "-" << setfill(' ') << endl;
	        for (int j = 0; j < recordCount; j++) 
	        {
	            string isbn = borrowRecords[j].isbn;
	            string borrowTimeStr = borrowRecords[j].borrowTimeStr;
	            string title = borrowRecords[j].title;
	            tm borrowTm = {};
	            istringstream ss(borrowTimeStr);
	            ss >> get_time(&borrowTm, "%Y-%m-%d %H:%M:%S");
	            if (ss.fail()) 
	            {
	                throw runtime_error("Invalid borrow time format for ISBN " + isbn);
	            }
	            time_t borrowTime = mktime(&borrowTm);
	            double secondsDiff = difftime(currentTime, borrowTime);
	            int daysDiff = static_cast<int>(secondsDiff / (60 * 60 * 24));
	
	            if (daysDiff > maxBorrowDays) 
	            {
	                hasOverdue = true;
	                int overdueDays = daysDiff - maxBorrowDays;
	                double fine = overdueDays * finePerDay;
	                totalFine += fine;
	                cout << left << setw(15) << isbn
	                     << setw(25) << (title.length() > 22 ? title.substr(0, 22) : title)
	                     << setw(20) << borrowTimeStr
	                     << right << setw(18) << overdueDays
	                     << setw(18) << fixed << setprecision(2) << fine << left << endl;
	            }
	        }
	        if (!hasOverdue) 
	        {
	            cout << "No overdue books found for " << username << "." << endl;
	        } else 
	        {
	            cout << "\nTotal Fine: RM " << fixed << setprecision(2) << totalFine << endl;
	        }
	    } catch (const exception& e) 
	    {
	        cout << "Error checking overdue books and fines: " << e.what() << endl;
	    }
	}
    int getCopyCount(const string& isbn);
    int getAvailableCopyCount(const string& isbn);
    bool removeCopy(const string& isbn, int copyNumber);
};
class LibrarySystem
{
private:
    UserManager userManager;
    BookManager bookManager;
    LibraryConfig config;
    void superAdminMenu() 
	{
        int choice;
        do 
		{
            clearScreen();
            cout << "\n=== SUPER ADMIN MENU ===" << endl;
            cout << "1. Register New Admin" << endl;
            cout << "2. Add New Book" << endl;
            cout << "3. Add Book Copies" << endl;
            cout << "4. List All Books" << endl;
            cout << "5. View All Admin Accounts" << endl;
            cout << "6. View All User Accounts" << endl;
            cout << "7. View All User History" << endl;
            cout << "8. Book Management" << endl;
            cout << "9. System Statistics" << endl;
            cout << "10. View Category Statistics" << endl;
            cout << "11. View Popular Books" << endl;
            cout << "12. Logout" << endl;
            cout << "Enter your choice: ";
            cin >> choice;
            cin.ignore();
            switch (choice) 
			{
                case 1: 
				{
                    clearScreen();
                    string username, password;
                    cout << "Enter new admin username: ";
                    getline(cin, username);
                    cout << "Enter new admin password: ";
                    password = getPassword();
                    
                    if (!userManager.registerAdmin(username, password)) 
					{
                        cout << "Admin registration failed." << endl;
                    }
                    break;
                }
                case 2: 
				{
                    clearScreen();
                    string isbn, title, author, category;
                    int year;
                    cout << "Enter book ISBN: ";
                    getline(cin, isbn);
                    cout << "Enter book title: ";
                    getline(cin, title);
                    cout << "Enter book author: ";
                    getline(cin, author);
                    cout << "Enter publication year: ";
                    cin >> year;
                    cin.ignore();
                    cout << "Enter book category: ";
                    getline(cin, category);
                    
                    if (bookManager.insertBook(isbn, title, author, year, category)) 
					{
                        cout << "Book added successfully!" << endl;
                    } else
					{
                        cout << "Failed to add book!" << endl;
                    }
                    break;
                }
                case 3: 
				{
                    clearScreen();
                    string isbn;
                    int copies;
                    cout << "Enter book ISBN to add copies: ";
                    getline(cin, isbn);
                    cout << "Enter number of copies to add (1-" << MAX_COPIES << "): ";
                    cin >> copies;
                    cin.ignore();
                    
                    bookManager.addBookCopies(isbn, copies);
                    break;
                }
                case 4:
                    clearScreen();
                    bookManager.listBooks();
                    break;
                case 5:
                    clearScreen();
                    userManager.displayAllAdmins();
                    break;
                case 6:
                    clearScreen();
                    userManager.displayAllUsers();
                    break;
                case 7:
                    clearScreen();
                    bookManager.displayAllUserHistory();
                    break;
                case 8:
                    bookManagementMenu();
                    break;
                case 9:
                    displaySystemStats();
                    break;
                case 10: 
				{
                    clearScreen();
                    CategoryStats stats[MAX_CATEGORIES];
                    int count = 0;
                    bookManager.getCategoryStats(stats, count);
                    
                    cout << "=== Category Statistics ===" << endl;
                    cout << left << setw(25) << "Category" 
                         << setw(15) << "Total Books" 
                         << setw(15) << "Available" 
                         << "Percentage Available" << endl;
                    cout << setfill('-') << setw(70) << "-" << setfill(' ') << endl;
                    
                    for (int i = 0; i < count; i++) 
					{
                        double percentage = (stats[i].bookCount > 0) ? 
                            (static_cast<double>(stats[i].availableCount) / stats[i].bookCount * 100) : 0;
                        
                        cout << setw(25) << stats[i].category 
                             << setw(15) << stats[i].bookCount 
                             << setw(15) << stats[i].availableCount
                             << fixed << setprecision(1) << percentage << "%" << endl;
                    }
                    break;
                }
                case 11: 
				{
                    clearScreen();
                    PopularBook popularBooks[MAX_POPULAR_BOOKS];
                    int count = 0;
                    bookManager.getPopularBooks(popularBooks, count);
                    
                    cout << "=== Most Popular Books ===" << endl;
                    cout << left << setw(15) << "Rank" 
                         << setw(20) << "ISBN" 
                         << setw(40) << "Title" 
                         << "Borrow Count" << endl;
                    cout << setfill('-') << setw(88) << "-" << setfill(' ') << endl;
                    
                    for (int i = 0; i < min(count, 10); i++) 
					{ 
                        string displayTitle = (popularBooks[i].title.length() > 35) 
                                           ? popularBooks[i].title.substr(0, 32) + "..."
                                           : popularBooks[i].title;
                        
                        cout << setw(15) << i+1 
                             << setw(25) << popularBooks[i].isbn 
                             << setw(40) << displayTitle 
                             << popularBooks[i].borrowCount << endl;
                    }
                    break;
                }
                case 12:
                    userManager.logout();
                    cout << "Logged out successfully!" << endl;
                    return;
                default:
                    cout << "Invalid choice!" << endl;
            }
            cout << "\nPress Enter to continue...";
            cin.ignore();
        } while (true);
    }
    void adminMenu() 
	{
        int choice;
        do 
		{
            clearScreen();
            cout << "\n=== ADMIN MENU ===" << endl;
            cout << "1. Add New Book" << endl;
            cout << "2. Add Book Copies" << endl;
            cout << "3. List All Books" << endl;
            cout << "4. View All User Accounts" << endl;
            cout << "5. View All User History" << endl;
            cout << "6. Book Management" << endl;
            cout << "7. System Statistics" << endl;
            cout << "8. Check All Users Overdue and Fines" << endl;
            cout << "9. Logout" << endl;
            cout << "Enter your choice: ";
            cin >> choice;
            cin.ignore();

            switch (choice) 
			{
                case 1: 
				{
                    clearScreen();
                    string isbn, title, author, category;
                    int year;
                    cout << "Enter book ISBN: ";
                    getline(cin, isbn);
                    cout << "Enter book title: ";
                    getline(cin, title);
                    cout << "Enter book author: ";
                    getline(cin, author);
                    cout << "Enter publication year: ";
                    cin >> year;
                    cin.ignore();
                    cout << "Enter book category: ";
                    getline(cin, category);
                    
                    if (bookManager.insertBook(isbn, title, author, year, category)) 
					{
                        cout << "Book added successfully!" << endl;
                    } else 
					{
                        cout << "Failed to add book!" << endl;
                    }
                    break;
                }
                case 2: 
				{
                    clearScreen();
                    string isbn;
                    int copies;
                    cout << "Enter book ISBN to add copies: ";
                    getline(cin, isbn);
                    cout << "Enter number of copies to add (1-" << MAX_COPIES << "): ";
                    cin >> copies;
                    cin.ignore();
                    
                    bookManager.addBookCopies(isbn, copies);
                    break;
                }
                case 3:
                    clearScreen();
                    bookManager.listBooks();
                    break;
                case 4:
                    clearScreen();
                    userManager.displayAllUsers();
                    break;
                case 5:
                    clearScreen();
                    bookManager.displayAllUserHistory();
                    break;
                case 6:
                    bookManagementMenu();
                    break;
                case 7:
                    displaySystemStats();
                    break;
	            case 8: 
	            {
	                clearScreen();
	                if (!userManager.isAdmin()) {
	                    cout << "Access denied. Admin privileges required." << endl;
	                } else {
	                    bookManager.checkAllUsersOverdueAndFines(config.maxBorrowDays, config.finePerDay, userManager);
	                }
	                break; 
	        	}
                case 9:
                    userManager.logout();
                    cout << "Logged out successfully!" << endl;
                    return;
                default:
                    cout << "Invalid choice!" << endl;
            }
            cout << "\nPress Enter to continue...";
            cin.ignore();
        } while (true);
    }
   void bookManagementMenu() 
	{
	    int choice;
	    do 
	    {
	        clearScreen();
	        cout << "\n=== BOOK MANAGEMENT ===" << endl;
	        cout << "1. Display Sorted Books (Title - Insertion Sort)" << endl;
	        cout << "2. Display Sorted Books (Year - Merge Sort)" << endl;
	        cout << "3. Search Book by Title (Binary Search)" << endl;
	        cout << "4. Edit Book" << endl;
	        cout << "5. Delete Book" << endl;
	        cout << "6. Search Book by ISBN" << endl;
	        cout << "7. Generate Report" << endl;
	        cout << "8. Return to Menu" << endl;
	        cout << "Enter your choice: ";
	        cin >> choice;
	        cin.ignore();
	
	        switch (choice) 
	        {
	            case 1:
	                clearScreen();
	                bookManager.displaySortedBooks(true);
	                break;
	            case 2:
	                clearScreen();
	                bookManager.displaySortedBooks(false);
	                break;
	            case 3: 
	            {
	                clearScreen();
	                string title;
	                cout << "Enter book title to search: ";
	                getline(cin, title);
	                bookManager.searchBookByTitle(title);
	                break;
	            }
	            case 4: 
	            {
	                clearScreen();
	                string isbn;
	                cout << "Enter ISBN of the book to edit: ";
	                getline(cin, isbn);
	                bookManager.editBook(isbn);
	                break;
	            }
	            case 5: 
	            {
	                clearScreen();
	                string isbn;
	                cout << "Enter ISBN of the book to delete: ";
	                getline(cin, isbn);
	                bookManager.deleteBook(isbn);
	                break;
	            }
	            case 6: 
	            {
	                clearScreen();
	                string isbn;
	                cout << "Enter ISBN of the book to search: ";
	                getline(cin, isbn);
	                Book* book = bookManager.searchBook(isbn);
	                if (book) 
	                {
	                    cout << "\nBook Found:" << endl;
	                    book->display();
	                } 
	                else 
	                {
	                    cout << "Book not found!" << endl;
	                }
	                break;
	            }
	            case 7: 
				{
				    clearScreen();
				    bookManager.generateSummaryReport();
				    break;
				}
	            case 8:
	                return;
	            default:
	                cout << "Invalid choice!" << endl;
	        }
	        cout << "\nPress Enter to continue...";
	        cin.ignore();
	    } while (true);
	}
    void displaySystemStats() 
	{
        clearScreen();
        SystemStats userStats = userManager.getSystemStats();
        ReportData bookStats = bookManager.generateReportData();
        cout << "=== SYSTEM STATISTICS ===" << endl;
        cout << "\nUser Statistics:" << endl;
        cout << "Super Admins: " << userStats.superAdminCount << endl;
        cout << "Admins: " << userStats.adminCount << endl;
        cout << "Regular Users: " << userStats.userCount << endl;
        cout << "Total Users: " << (userStats.superAdminCount + userStats.adminCount + userStats.userCount) << endl;
        cout << "\nBook Statistics:" << endl;
        cout << "Total Books: " << bookStats.totalBooks << endl;
        cout << "Available: " << bookStats.availableBooks << endl;
        cout << "Borrowed: " << bookStats.borrowedBooks << endl;
        if (bookStats.totalBooks > 0) 
		{
            cout << "Borrow Rate: " 
                 << (static_cast<double>(bookStats.borrowedBooks) / bookStats.totalBooks * 100)
                 << "%" << endl;
        }
    }
     void userMenu(User* currentUser) 
	{
        int choice;
        do 
		{
            clearScreen();
            cout << "\n=== USER MENU ===" << endl;
            cout << "1. List All Books" << endl;
            cout << "2. Search Book" << endl;
            cout << "3. Borrow Book" << endl;
            cout << "4. Return Book" << endl;
            cout << "5. View My History" << endl;
            cout << "6. Check Overdue Books and Fines" << endl;
            cout << "7. Generate Report" <<endl;
            cout << "8. Logout" << endl;
            cout << "Enter your choice: ";
            cin >> choice;
            cin.ignore();
            switch (choice) 
			{
                case 1:
                    clearScreen();
                    bookManager.listBooks();
                    break;
                case 2: 
				{
                    clearScreen();
                    string isbn;
                    cout << "Enter book ISBN to search: ";
                    getline(cin, isbn);
                    Book* book = bookManager.searchBook(isbn);
                    if (book) 
					{
                        cout << "\nBook Found:" << endl;
                        book->display();
                    } else 
					{
                        cout << "Book not found or all copies are borrowed!" << endl;
                    }
                    break;
                }
                case 3:
				{
                    clearScreen();
                    string isbn;
                    cout << "Enter ISBN of the book to borrow: ";
                    getline(cin, isbn);
                    bookManager.borrowBook(isbn, currentUser->getId());
                    break;
                }
                case 4: 
				{
                    clearScreen();
                    string isbn;
                    cout << "Enter ISBN of the book to return: ";
                    getline(cin, isbn);
                    bookManager.returnBook(isbn, currentUser->getId());
                    break;
                }
                case 5: 
				{
                    bookManager.displayUserHistory(currentUser->getId());
                    break;
                }
                case 6: 
				{ 
	                clearScreen();
	                bookManager.checkOverdueAndFines(currentUser->getId(), config.maxBorrowDays, config.finePerDay);
	                break;
            	}
            	case 7: 
				{
	                bookManager.generateUserSummaryReport(currentUser->getId());
	                break;
	            }
                case 8:
                    userManager.logout();
                    cout << "Logged out successfully!" << endl;
                    return;
                default:
                    cout << "Invalid choice!" << endl;
            }
            cout << "\nPress Enter to continue...";
            cin.ignore();
        } while (true);
    }       
    void loginMenu(Role role)
	{
        clearScreen();
        string username, password;
        cout << "=== " << (role == SUPERADMIN ? "SUPER ADMIN" : (role == ADMIN ? "ADMIN" : "USER")) << " LOGIN ===" << endl;
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        password = getPassword();
        if (userManager.login(username, password, role)) 
		{
            cout << "Login successful!" << endl;
            cout << "Press Enter to continue...";
            cin.ignore();
            
            if (userManager.isSuperAdmin()) 
			{
                superAdminMenu();
            } else if (userManager.isAdmin()) 
			{
                adminMenu();
            } else 
			{
                userMenu(userManager.getCurrentUser());
            }
        } else 
		{
            cout << "Invalid username or password for selected role!" << endl;
            cout << "Press Enter to continue...";
            cin.ignore();
        }
    }
    void registerUserMenu() 
	{
        clearScreen();
        cout << "=== USER REGISTRATION ===" << endl;
        string username, password;
	    cout << "Enter username: ";
	    getline(cin, username);
	    cout << "Enter password (must be at least 6 characters): ";
    	password = getPassword();
        if (userManager.searchUser(username)) 
		{
	        cout << "\nRegistration failed. Username already exists!" << endl;
	        cout << "\nPress Enter to return to main menu...";
	        cin.ignore();
	        return;
	    }
	    if (password.length() < 6) 
		{
	        cout << "\nRegistration failed. Password must be at least 6 characters!" << endl;
	        cout << "\nPress Enter to return to main menu...";
	        cin.ignore();
	        return;
	    }
	    if (userManager.registerUser(username, password)) 
		{
	        cout << "\nRegistration successful!" << endl;
	    } else 
		{
	        cout << "\nRegistration failed. Please try again." << endl;
	    }
	    
	    cout << "\nPress Enter to return to main menu...";
	    cin.ignore();
	}
public:
	LibrarySystem()
	{
		config.libraryName = "TCLL Library";
		config.maxBorrowDays = 5;
		config.finePerDay = 1.0;
	}
	
	LibraryConfig getConfig()const
	{
		return config;
	}
	void generateSummaryReport();
    void run() 
	{
        while (true) 
		{
            clearScreen();
            cout << "\n=== Welcome TCLL Book Rental System ===" << endl;
            cout << "1. Login as User" << endl;
            cout << "2. Login as Admin" << endl;
            cout << "3. Login as Super Admin" << endl;
            cout << "4. Register as User" << endl;
            cout << "5. Exit" << endl;
            cout << "Enter your choice: ";
            int choice;
            cin >> choice;
            cin.ignore();
            switch (choice) 
			{
                case 1:
                    loginMenu(REGULAR_USER);
                    break;
                case 2:
				    loginMenu(ADMIN);
				    break;
				case 3:
				    loginMenu(SUPERADMIN);
				    break;
				case 4:
				    registerUserMenu();
				    break;
				case 5:
				    cout << "Exiting system..." << endl;
				    return;
				default:
				    cout << "Invalid choice! Please try again." << endl;
				    cout << "Press Enter to continue...";
				    cin.ignore();
            }
        }
    }
};
int main() 
{
    LibrarySystem library;
    library.run();
    return 0;
}