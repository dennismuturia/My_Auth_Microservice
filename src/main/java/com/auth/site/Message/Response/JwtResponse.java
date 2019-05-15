package com.auth.site.Message.Response;

public class JwtResponse {
    private String token;
    private String type = "Bearer";

    //Constructor token
    public JwtResponse(String accessToken){
        this.token = accessToken;
    }

    public  String getAccessToken(){
        return token;
    }
    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }

    public String getTokenType() {
        return type;
    }

    public void setTokenType(String tokenType) {
        this.type = tokenType;
    }
}
