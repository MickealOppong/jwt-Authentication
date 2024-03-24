package com.opp.todo.exceptions;

public class UsernameAlreadyExistException extends RuntimeException{

    public UsernameAlreadyExistException(String message){
        super(message);
    }

    public UsernameAlreadyExistException(String message,Throwable cause){
        super(message,cause
        );
    }

}
