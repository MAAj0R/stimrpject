class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
         :omniauthable
   def self.find_for_steam_oauth(auth, signed_in_resource=nil)      
  user = User.where(provider: auth.provider, uid: auth.uid).first       
  # The User was found in our database    
  return user if user    
  # Check if the User is already registered without Facebook      
  
  User.create(
    name: auth.extra.raw_info.name,
    provider: auth.provider, uid: auth.uid,
    
    password: Devise.friendly_token[0,20])  
end
end
