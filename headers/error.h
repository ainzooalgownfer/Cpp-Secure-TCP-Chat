//
// Created by moham on 16/01/2026.
//

#ifndef CRYPTO__ERROR_H
#define CRYPTO__ERROR_H
#include <exception>
#include <string>

using namespace std;

class Error : public std::exception {

private:
    string message;

public:

    explicit Error(const string& m) : message(m) {}


    virtual const char* what() const noexcept override {
        return message.c_str();
    }
};
#endif //CRYPTO__ERROR_H