import mongoose from 'mongoose';

const crypto = require('crypto');
const uuidv1 = require('uuid/v1');
const { Schema } = mongoose;

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
        maxlength: 32,
        trim: true
    },
    lastname: {
        type: String,
        required: false,
        maxlength: 32,
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    userinfo: {
        type: String,
        trim: true,
    },
    //TODO: come back here
    encry_password: {
        type: String,
        required: true
    },
    salt: String,
    role: {
        type: Number,
        default: 0
    },
    purchases: {
        type: Array,
        default: []
    }
});

userSchema.virtual('password').set(function(password){
    // @ _password local private variable
this._password = password;
this.salt = uuidv1();
this.encry_password = this.securePassword(password);
}).get(function(){
    return this._password;
})

userSchema.method = {
    authenticate: function(plainpassword){
        return this.securePassword(plainpassword) === this.encry_password
    },
    securePassword: function (plainpassword) {
        if (!plainpassword) return '';

        try {
            return crypto.createHmac('sha256', this.salt)
            .update(plainpassword)
            .digest('hex');
        } catch (err) {
            // As per the rules of mongo db an empty string can not be stored!
            return '';
        }
    }
}

module.exports = mongoose.Schema('User', userSchema);